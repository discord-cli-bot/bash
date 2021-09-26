/* list.c - Functions for manipulating linked lists of objects. */

/* Copyright (C) 1996-2009 Free Software Foundation, Inc.

   This file is part of GNU Bash, the Bourne Again SHell.

   Bash is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   Bash is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with Bash.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"

#if defined (HAVE_UNISTD_H)
#  ifdef _MINIX
#    include <sys/types.h>
#  endif
#  include <unistd.h>
#endif

#include "shell.h"

/* A global variable which acts as a sentinel for an `error' list return. */
GENERIC_LIST global_error_list;

/* Reverse the chain of structures in LIST.  Output the new head
   of the chain.  You should always assign the output value of this
   function to something, or you will lose the chain. */
GENERIC_LIST *
list_reverse (list)
     GENERIC_LIST *list;
{
  register GENERIC_LIST *next, *prev;

  for (prev = (GENERIC_LIST *)NULL; list; )
    {
      next = list->next;
      list->next = prev;
      prev = list;
      list = next;
    }
  return (prev);
}

/* Return the number of elements in LIST, a generic list. */
int
list_length (list)
     GENERIC_LIST *list;
{
  register int i;

  for (i = 0; list; list = list->next, i++);
  return (i);
}

/* Append TAIL to HEAD.  Return the header of the list. */
GENERIC_LIST *
list_append (head, tail)
     GENERIC_LIST *head, *tail;
{
  register GENERIC_LIST *t_head;

  if (head == 0)
    return (tail);

  for (t_head = head; t_head->next; t_head = t_head->next)
    ;
  t_head->next = tail;
  return (head);
}
