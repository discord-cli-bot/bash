#if !defined (_OSAIBOT_H_)
#define _OSAIBOT_H_

#include "stdc.h"

int osaibot_getc(void);
int osaibot_ungetc(int c);

void osaibot_prompt(char *prompt);

int osaibot_init(void);

#endif /* _OSAIBOT_H_ */
