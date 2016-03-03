#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// Checks if user pointer is 
static bool 
valid_usr_ptr(const void *uaddr)
{
  // Checks if uaddr is below PHYS_BASE, above 0x08048000 (address given in directions), and not unmapped
  if(is_user_vaddr (uaddr) && uaddr >= (void *)0x08048000 && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL)
    {
      return true;
    }
  return false;
}

// Check if argument addresses are valid
static bool
valid_args(int num_args, struct intr_frame *f)
{
  void *ptr = f->esp;
  int i = 0;
  for(i = 0; i < num_args; i++)
    {
      ptr += 4;
      if(!valid_usr_ptr (ptr))
        {
          return false;
        }
    }
  return true;
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
syscall_write (struct intr_frame *f)
{
  if(!valid_args (3, f))
    {
      syscall_exit (1);
    }

  // Multiples of 4 since variable takes 4 bytes
  int fd = *((int *)(f->esp + 4));
  void *buffer = (void *)(f->esp + 8);
  unsigned size = *((unsigned *)(f->esp + 12));

  // Check buffer size
  if(!valid_usr_ptr (buffer) || !valid_usr_ptr (buffer + size - 1))
    {
      f->eax = -1; // Return -1 for error
      //syscall_exit (1);
    }

  if(fd <= 0 || fd >= 128) // Since we only have file descriptors 0-127
    {
      f->eax = -1; // Return -1 for error
      //syscall_exit (1);
    }
  else if(fd == 1)
    {
      // write to console
      
      // If size is bigger than a few hunder bytes, break it up into chunks (chose 512)
      unsigned size_remaining = size;
      char *cbuff = buffer;
      while(size_remaining > 512)
        {
          putbuf (cbuff, 512); // Write 512 bytes to buffer
          size_remaining -= 512; // Subtract 512 from remaining
          cbuff += 512; // Add 512 to address of where to write from in next iteration
        }
      putbuf (cbuff, size_remaining);
    }
  else
    {
      // write to file
      
      // Check if index at fd is a null pointer
      if(thread_current ()->fd_table[fd] == NULL)
        {
          f->eax = -1; // Return -1 for error
          syscall_exit(1);
        }
      else
        {
          f->eax = file_write(thread_current ()->fd_table[fd], buffer, size); // Return the value
        }
    }

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

  if(!valid_usr_ptr (f->esp))
    {
      syscall_exit (1);
    }
  switch (*syscall_num)
    {
      case SYS_HALT:
        {
          syscall_halt (f);
          break;
        }
      case SYS_EXIT:
        {
          syscall_exit (0);
          break;
        }
      case SYS_EXEC:
        {
          syscall_exec (f);
          break;
        }
      case SYS_WAIT:
        {
          syscall_wait (f);
          break;
        }
      case SYS_CREATE:
        {
          syscall_create (f);
          break;
        }
      case SYS_REMOVE:
        {
          syscall_remove (f);
          break;
        }
      case SYS_OPEN:
        {
          syscall_open (f);
          break;
        }
      case SYS_FILESIZE:
        {
          syscall_filesize (f);
          break;
        }
      case SYS_READ:
        {
          syscall_read (f);
          break;
        }
      case SYS_WRITE:
        {
          syscall_write (f);
          break;
        }
      case SYS_SEEK:
        {
          syscall_seek (f);
          break;
        }
      case SYS_TELL:
        {
          syscall_tell (f);
          break;
        }
      case SYS_CLOSE:
        {
          syscall_close (f);
          break;
        }
      default:
        {
          syscall_exit (1);
          break;
        }
    }

  //printf ("system call!\n");
  //thread_exit ();
}
