/* Glue between the Ziggurat staticlib (ziggurat.h) and the OpenThread RCP. */

#ifndef ZIGGURAT_GLUE_H_
#define ZIGGURAT_GLUE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Start the embedded stack on the RCP's otInstance, on the first PROP_ZIGGURAT
 * write. Idempotent after the first call. */
void ziggurat_glue_start(void);

bool ziggurat_glue_started(void);

/* Queue one unsolicited PROP_ZIGGURAT frame to the host. Implemented in
 * ziggurat_ncp.cpp (needs the NCP encoder). */
bool ziggurat_ncp_host_send(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ZIGGURAT_GLUE_H_ */
