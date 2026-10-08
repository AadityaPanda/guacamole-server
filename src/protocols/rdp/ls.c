/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "fs.h"
#include "ls.h"

#include <guacamole/client.h>
#include <guacamole/mem.h>
#include <guacamole/protocol.h>
#include <guacamole/socket.h>
#include <guacamole/stream.h>
#include <guacamole/user.h>
#include <winpr/file.h>
#include <winpr/nt.h>
#include <winpr/shell.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * File details in RDP drive listings.
 *
 * Same entry format as the SFTP listings in src/common-ssh/sftp.c:
 * `"<path>": {"mime": ..., "size": ..., "mtime": ...}`. The drive is a
 * directory on the guacd host, so permissions and ownership (all guacd's own
 * service user) carry no meaning here and are not sent. Size is sent for
 * files only; mtime only when known.
 */

/**
 * Seconds between the Windows epoch (1601-01-01) and the UNIX epoch - the
 * inverse of WINDOWS_TIME() in fs.h, which stores times as 100-nanosecond
 * intervals since 1601.
 */
#define GUAC_RDP_LS_EPOCH_DELTA ((uint64_t) 11644473600)

/**
 * Writes one directory entry as `"<path>": {<details>}`, mirroring
 * guac_common_json_write_property() (leading comma, property count) so the
 * surrounding stream/blob flow control is unchanged.
 *
 * @return
 *     Non-zero if at least one blob was written, zero otherwise.
 */
static int guac_rdp_ls_write_entry(guac_user* user, guac_stream* stream,
        guac_common_json_state* json_state, const char* path,
        const char* mimetype, const guac_rdp_fs_file* file) {

    int blob_written = 0;
    char buffer[64];

    if (json_state->properties_written != 0)
        blob_written |= guac_common_json_write(user, stream,
                json_state, ",", 1);

    blob_written |= guac_common_json_write_string(user, stream,
            json_state, path);

    blob_written |= guac_common_json_write(user, stream,
            json_state, ":{\"mime\":", 9);

    blob_written |= guac_common_json_write_string(user, stream,
            json_state, mimetype);

    /* Size is meaningful for files only */
    if (!(file->attributes & FILE_ATTRIBUTE_DIRECTORY)) {
        snprintf(buffer, sizeof(buffer), ",\"size\":%llu",
                (unsigned long long) file->size);
        blob_written |= guac_common_json_write(user, stream,
                json_state, buffer, strlen(buffer));
    }

    /* A zero Windows timestamp means the time is unknown */
    if (file->mtime != 0) {
        snprintf(buffer, sizeof(buffer), ",\"mtime\":%llu",
                (unsigned long long) (file->mtime / 10000000
                    - GUAC_RDP_LS_EPOCH_DELTA));
        blob_written |= guac_common_json_write(user, stream,
                json_state, buffer, strlen(buffer));
    }

    blob_written |= guac_common_json_write(user, stream,
            json_state, "}", 1);

    json_state->properties_written++;

    return blob_written;

}

int guac_rdp_ls_ack_handler(guac_user* user, guac_stream* stream,
        char* message, guac_protocol_status status) {

    int blob_written = 0;
    const char* filename;

    guac_rdp_ls_status* ls_status = (guac_rdp_ls_status*) stream->data;

    /* If unsuccessful, free stream and abort */
    if (status != GUAC_PROTOCOL_STATUS_SUCCESS) {
        guac_rdp_fs_close(ls_status->fs, ls_status->file_id);
        guac_user_free_stream(user, stream);
        guac_mem_free(ls_status);
        return 0;
    }

    /* While directory entries remain */
    while ((filename = guac_rdp_fs_read_dir(ls_status->fs,
                    ls_status->file_id)) != NULL
            && !blob_written) {

        char absolute_path[GUAC_RDP_FS_MAX_PATH];

        /* Skip current and parent directory entries */
        if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0)
            continue;

        /* Concatenate into absolute path - skip if invalid */
        if (!guac_rdp_fs_append_filename(absolute_path,
                    ls_status->directory_name, filename)) {

            guac_user_log(user, GUAC_LOG_DEBUG,
                    "Skipping filename \"%s\" - filename is invalid or "
                    "resulting path is too long", filename);

            continue;
        }

        /* Attempt to open file to determine type */
        int file_id = guac_rdp_fs_open(ls_status->fs, absolute_path,
                GENERIC_READ, 0, FILE_OPEN, 0);
        if (file_id < 0)
            continue;

        /* Get opened file */
        guac_rdp_fs_file* file = guac_rdp_fs_get_file(ls_status->fs, file_id);
        if (file == NULL) {
            guac_user_log(user, GUAC_LOG_DEBUG, "%s: Successful open produced "
                    "bad file_id: %i", __func__, file_id);
            return 0;
        }

        /* Determine mimetype */
        const char* mimetype;
        if (file->attributes & FILE_ATTRIBUTE_DIRECTORY)
            mimetype = GUAC_USER_STREAM_INDEX_MIMETYPE;
        else
            mimetype = "application/octet-stream";

        /* Write entry: an object value with size and
         * modification time, not the bare mimetype string. */
        blob_written |= guac_rdp_ls_write_entry(user, stream,
                &ls_status->json_state, absolute_path, mimetype, file);

        guac_rdp_fs_close(ls_status->fs, file_id);

    }

    /* Complete JSON and cleanup at end of directory */
    if (filename == NULL) {

        /* Complete JSON object */
        guac_common_json_end_object(user, stream, &ls_status->json_state);
        guac_common_json_flush(user, stream, &ls_status->json_state);

        /* Clean up resources */
        guac_rdp_fs_close(ls_status->fs, ls_status->file_id);
        guac_mem_free(ls_status);

        /* Signal of stream */
        guac_protocol_send_end(user->socket, stream);
        guac_user_free_stream(user, stream);

    }

    guac_socket_flush(user->socket);
    return 0;

}

