#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// Checks if user pointer is 
static bool valid_usr_ptr(uint32_t *pd, const void *uaddr)
{
  // Checks if uaddr is below PHYS_BASE, above 0x08048000 (address given in directions), and not unmapped
  if(is_user_vaddr (uaddr) && uaddr >= (void *)0x08048000 && pagedir_get_page (pd, uaddr) != NULL)
    {
      return true;
    }
  return false;
}

static void
syscall_halt (struct intr_frame *f UNUSED)
{
}


static void
syscall_exit (int status UNUSED)
{
  // TODO: NEED TO DO SOMETHING WITH STATUS
  thread_exit ();
}

static void
syscall_exec (struct intr_frame *f UNUSED)
{
}

static void
syscall_wait (struct intr_frame *f UNUSED)
{
}

static void
syscall_create (struct intr_frame *f UNUSED)
{
}

static void
syscall_remove (struct intr_frame *f UNUSED)
{
}

static void
syscall_open (struct intr_frame *f UNUSED)
{
}

static void
syscall_filesize (struct intr_frame *f UNUSED)
{
}

static void
syscall_read (struct intr_frame *f UNUSED)
{
}

static void
syscall_write (struct intr_frame *f UNUSED)
{
}

static void
syscall_seek (struct intr_frame *f UNUSED)
{
}

static void
syscall_tell (struct intr_frame *f UNUSED)
{
}

static void
syscall_close (struct intr_frame *f UNUSED)
{
}

static void
syscall_handler (struct intr_frame *f) 
{
  // Check if esp is valid
  int *syscall_num = f->esp;

  if(!valid_usr_ptr(thread_current ()->pagedir, f->esp))
    {
      syscall_exit(-1);
    }
  switch (*syscall_num)
    {
      case SYS_HALT:
        {
          syscall_halt(f);
          break;
        }
      case SYS_EXIT:
        {
          syscall_exit(0);
          break;
        }
      case SYS_EXEC:
        {
          syscall_exec(f);
          break;
        }
      case SYS_WAIT:
        {
          syscall_wait(f);
          break;
        }
      case SYS_CREATE:
        {
          syscall_create(f);
          break;
        }
      case SYS_REMOVE:
        {
          syscall_remove(f);
          break;
        }
      case SYS_OPEN:
        {
          syscall_open(f);
          break;
        }
      case SYS_FILESIZE:
        {
          syscall_filesize(f);
          break;
        }
      case SYS_READ:
        {
          syscall_read(f);
          break;
        }
      case SYS_WRITE:
        {
          syscall_write(f);
          break;
        }
      case SYS_SEEK:
        {
          syscall_seek(f);
          break;
        }
      case SYS_TELL:
        {
          syscall_tell(f);
          break;
        }
      case SYS_CLOSE:
        {
          syscall_close(f);
          break;
        }
      default:
        {
          syscall_exit(-1);
          break;
        }
    }

  //printf ("system call!\n");
  //thread_exit ();
}
