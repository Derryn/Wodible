#include <stdio.h> 
#include <sys/types.h> 
#include <unistd.h>
main() { 
  int i,n; 
  printf("i is equal to");
  pid_t child; 
  printf("How many processes do you want? \n"); 
  scanf("%d",&n); 
  for (i=1; i<n; ++i) 
    if (child = fork()) break; 
  printf("This is process : %ld, with parent : %ld \n", 
    (long)getpid(), (long)getppid()); 
}