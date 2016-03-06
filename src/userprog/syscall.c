#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/synch.h"
#include "devices/input.h"

static void syscall_handler (struct intr_frame *);
struct lock file_lock;

void
syscall_init (void) 
{
  lock_init (&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// Checks if user pointer is 
static bool 
valid_usr_ptr(const void *uaddr)
{
  // Checks if uaddr is below PHYS_BASE, 
  // above 0x08048000 (address given in directions), 
  // and not unmapped
  if (is_user_vaddr (uaddr) 
      && uaddr >= (void *)0x08048000 
      && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL)
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
  for (i = 0; i < num_args; i++)
    {
      ptr += 4;
      if (!valid_usr_ptr (ptr))
        {
          return false;
        }
    }
  return true;
}

// In general, when there is an error it is handled by syscall_exit (-1)

static void
syscall_halt (struct intr_frame *f UNUSED)
{
  shutdown_power_off ();
}


static void
syscall_exit (int status UNUSED)
{
  // TODO: NEED TO DO SOMETHING WITH STATUS
  thread_exit ();
}

static void
syscall_exec (struct intr_frame *f)
{
  if(!valid_args (1, f))
    {
      f->eax = -1;
      syscall_exit (-1);
    }
  char* cmd_line = (char *)(f->esp + 4);
  if (!valid_usr_ptr (cmd_line))
    {
      f->eax = -1;
      syscall_exit(-1);
    }
  f->eax = process_execute (cmd_line);
}

static void
syscall_wait (struct intr_frame *f)
{
  if(!valid_args (1, f))
    {
      f->eax = -1;
      syscall_exit (-1);
    }
  pid_t pid = *((pid_t *)(f->esp + 4));
  f->eax = process_wait (pid);
}

static void
syscall_create (struct intr_frame *f)
{
  if(!valid_args (2, f))
    {
      f->eax = false;
      syscall_exit (-1);
    }
  char* file_name = (char *)(f->esp + 4);
  int file_size = *(int*)(f->esp + 8);
  
  if (!valid_usr_ptr (file_name))
    {
      f->eax = false;
      syscall_exit (-1);
    }
  lock_acquire (&file_lock);
  bool success = filesys_create(file_name, file_size);
  lock_release (&file_lock);
  f->eax = success;
}

static void
syscall_remove (struct intr_frame *f)
{
  if(!valid_args (1, f))
    {
      f->eax = false;
      syscall_exit (-1);
    }
  char* file_name = (char *)(f->esp + 4);
  if (!valid_usr_ptr (file_name))
    {
      f->eax = false;
      syscall_exit(-1);
    }
  lock_acquire (&file_lock);
  bool ret = filesys_remove (file_name);
  lock_release (&file_lock);
  f->eax = ret;
}

static void
syscall_open (struct intr_frame *f)
{
  if(!valid_args (1, f))
    {
      f->eax = false;
      syscall_exit (-1);
    }
  char* file_name = (char *)(f->esp + 4);
  if (!valid_usr_ptr (file_name)) // Check argument
    {
      syscall_exit (-1);
    }
  
  lock_acquire (&file_lock);
  struct file* open_file = filesys_open (file_name);
  lock_release (&file_lock);

  if(!open_file)
    {
      f->eax = -1;
    }
  else
    {
      int i;
      for (i = 2; i < 128; i++)
        {
          // Loop is to 128 because that is the size of the fd_table
          // Finds the first value in the table that is not NULL
          // Which is the first spot available to set the fd
          if (thread_current ()->fd_table[i] == NULL)
            break;
        }
      if (i == 128)
        f->eax = -1;
      else 
        { 
          thread_current ()->fd_table[i] = open_file;
          f->eax = i;
        }
    }

}

static void
syscall_filesize (struct intr_frame *f)
{
  if(!valid_args (1, f))
    {
      f->eax = -1;
      syscall_exit (-1);
    }

  int fd = *((int *)(f->esp + 4));
  struct file* file_ptr = thread_current ()->fd_table[fd];
  
  // Check if fd is a valid index
  // Note: fd[0] and fd[1] should be NULL
  if( fd < 0 || fd >= 128 || file_ptr == NULL)
    {
      f->eax = -1;
      syscall_exit (-1);
    }
  
  lock_acquire (&file_lock);
  f->eax = file_length (file_ptr);
  lock_release (&file_lock);
}

static void
syscall_read (struct intr_frame *f)
{
  if (!valid_args (3, f))
    {
      f->eax = -1;
      syscall_exit (-1);
    }

  // Multiples of 4 since variable takes 4 bytes
  int fd = *((int *)(f->esp + 4));
  void *buffer = (void *)(f->esp + 8);
  unsigned size = *((unsigned *)(f->esp + 12));

  // Check buffer size
  if (!valid_usr_ptr (buffer) || !valid_usr_ptr (buffer + size - 1))
    {
      f->eax = -1; // Return -1 for error
      syscall_exit (-1);
    }

  if (fd < 0 || fd >= 128 || fd == 1) // Since we only have file descriptors 0-127
    {
      // Also, fd == 1 => error, since its STOUT_FILENO
      f->eax = -1; // Return -1 for error
      syscall_exit (-1);
    }
  else if (fd == 0)
    {
      // read from console
      char * cbuff = buffer;
      unsigned i; // Unsigned so that we're comparing unsigned types
      for(i = 0; i < size; i++)
        {
          cbuff[i] = input_getc();
        }
      f->eax = size;
    }
  else
    {
      // read from file
      
      // Check if index at fd is a null pointer
      if (thread_current ()->fd_table[fd] == NULL)
        {
          f->eax = -1; // Return -1 for error
          syscall_exit (-1);
        }
      else
        {
          lock_acquire(&file_lock);
          f->eax = file_read(thread_current ()->fd_table[fd], buffer, size); 
          lock_release(&file_lock);
          // Return the value
        }
    }

}

static void
syscall_write (struct intr_frame *f)
{
  if (!valid_args (3, f))
    {
      f->eax = -1;
      syscall_exit (-1);
    }

  // Multiples of 4 since variable takes 4 bytes
  int fd = *((int *)(f->esp + 4));
  void *buffer = (void *)(f->esp + 8);
  unsigned size = *((unsigned *)(f->esp + 12));

  // Check buffer size
  if (!valid_usr_ptr (buffer) || !valid_usr_ptr (buffer + size - 1))
    {
      f->eax = -1; // Return -1 for error
      syscall_exit (-1);
    }

  if (fd <= 0 || fd >= 128) // Since we only have file descriptors 0-127
    {
      // Also there is an error if fd == 0, since its STIN_FILENO
      f->eax = -1; // Return -1 for error
      syscall_exit (-1);
    }
  else if (fd == 1)
    {
      // write to console
      
      // If size is bigger than a few hunder bytes, 
      // break it up into chunks (chose 512)
      unsigned size_remaining = size;
      char *cbuff = buffer;
      while(size_remaining > 512)
        {
          putbuf (cbuff, 512); // Write 512 bytes to buffer
          size_remaining -= 512; // Subtract 512 from remaining
          cbuff += 512; // Add 512 to address of where to write
        }
      putbuf (cbuff, size_remaining);
    }
  else
    {
      // write to file
      
      // Check if index at fd is a null pointer
      if (thread_current ()->fd_table[fd] == NULL)
        {
          f->eax = -1; // Return -1 for error
          syscall_exit (-1);
        }
      else
        {
          lock_acquire(&file_lock);
          f->eax = file_write(thread_current ()->fd_table[fd], buffer, size); 
          lock_release(&file_lock);
          // Return the value
        }
    }

}

static void
syscall_seek (struct intr_frame *f)
{
  if(!valid_args (2, f))
    {
      syscall_exit (-1);
    }

  int fd = *((int *)(f->esp + 4));
  unsigned position = *((unsigned *)(f->esp + 8));
  
  // Check if fd is a valid index
  // Note: fd[0] and fd[1] should be NULL
  if( fd < 0 || fd >= 128 || thread_current ()->fd_table[fd] == NULL)
    {
      syscall_exit (-1);
    }
  struct file *file_ptr = thread_current ()->fd_table[fd];
  
  lock_acquire (&file_lock);
  file_seek(file_ptr, position);
  lock_release (&file_lock);
}

static void
syscall_tell (struct intr_frame *f)
{
  if(!valid_args (1, f))
    {
      f->eax = 0;
      syscall_exit (-1);
    }

  int fd = *((int *)(f->esp + 4));
  
  // Check if fd is a valid index
  // Note: fd[0] and fd[1] should be NULL
  if( fd < 0 || fd >= 128 || thread_current ()->fd_table[fd] == NULL)
    {
      f->eax = 0;
      syscall_exit (-1);
    }
  struct file *file_ptr = thread_current ()->fd_table[fd];
  
  lock_acquire (&file_lock);
  f->eax = file_tell(file_ptr);
  lock_release (&file_lock);
}

static void
syscall_close (struct intr_frame *f)
{
  if(!valid_args (1, f))
    {
      syscall_exit (-1);
    }

  int fd = *((int *)(f->esp + 4));
  
  // Check if fd is a valid index
  // Note: fd[0] and fd[1] should be NULL
  if( fd < 0 || fd >= 128 || thread_current ()->fd_table[fd] == NULL)
    {
      syscall_exit (-1);
    }
  struct file *file_ptr = thread_current ()->fd_table[fd];
  
  lock_acquire (&file_lock);
  file_close(file_ptr);
  lock_release (&file_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  // Check if esp is valid
  int *syscall_num = f->esp;

  if(!valid_usr_ptr (f->esp))
    {
      syscall_exit (-1);
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
          syscall_exit (-1);
          break;
        }
    }

  //printf ("system call!\n");
  //thread_exit ();
}
