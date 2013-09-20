/* Generate tables for CCSDS code
 * Copyright 2002 Phil Karn, KA9Q
 * May be used under the terms of the GNU Lesser General Public License (LGPL)
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "char.h"
#include "rs-common.h"
#include "fec.h"

int main(){
  struct rs *rs;
  int i;

  rs = init_rs_char(8,0x187,112,11,32,0); /* CCSDS standard */
  assert(rs != NULL);
  printf("char CCSDS_alpha_to[] = {");
  for(i=0;i<256;i++){
    if((i % 16) == 0)
      printf("\n");
    printf("0x%02x,",rs->alpha_to[i]);
  }
  printf("\n};\n\nchar CCSDS_index_of[] = {");
  for(i=0;i<256;i++){
    if((i % 16) == 0)
      printf("\n");
    printf("%3d,",rs->index_of[i]);
  }
  printf("\n};\n\nchar CCSDS_poly[] = {");
  for(i=0;i<33;i++){
    if((i % 16) == 0)
      printf("\n");

    printf("%3d,",rs->genpoly[i]);
  }
  printf("\n};\n");
  exit(0);
}
