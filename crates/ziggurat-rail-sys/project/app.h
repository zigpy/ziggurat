#ifndef APP_H
#define APP_H

#if defined(SL_COMPONENT_CATALOG_PRESENT)
#include "sl_component_catalog.h"
#endif

void app_init(void);
void app_process_action(void);
void app_exit(void);

#endif
