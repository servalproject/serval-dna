
#define POLY  0xAE3  /* or use the other polynomial, 0xC75 */
#include <inttypes.h>

static uint32_t golay(uint32_t cw) 
/* This function calculates [23,12] Golay codewords. 
   The format of the returned longint is 
   [checkbits(11),data(12)]. */ 
{ 
  int i; 
  uint32_t c; 
  cw&=0xfffl; 
  c=cw; /* save original codeword */ 
  for (i=1; i<=12; i++)  /* examine each data bit */ 
    { 
      if (cw & 1)        /* test data bit */ 
        cw^=POLY;        /* XOR polynomial */ 
      cw>>=1;            /* shift intermediate result */
    } 
  return((cw<<12)|c);    /* assemble codeword */ 
}

static int parity(uint32_t cw) 
/* This function checks the overall parity of codeword cw.
   If parity is even, 0 is returned, else 1. */ 
{ 
  uint8_t p; 
  
  /* XOR the bytes of the codeword */ 
  p=cw & 0xFF; 
  p^=(cw>>8) & 0xFF; 
  p^=(cw>>16) & 0xFF; 

  /* XOR the halves of the intermediate result */ 
  p=p ^ (p>>4); 
  p=p ^ (p>>2); 
  p=p ^ (p>>1); 

  /* return the parity result */ 
  return(p & 1); 
}

int golay_encode(uint8_t *data)
{
  uint32_t cw = data[0] | (data[1]<<8) | (data[2]<<16);
  cw = golay(cw);
  if (parity(cw))
    cw|=0x800000l;
  data[0]=cw&0xFF;
  data[1]=(cw>>8)&0xFF;
  data[2]=(cw>>16)&0xFF;
  return 0;
}

static uint32_t syndrome(uint32_t cw) 
/* This function calculates and returns the syndrome 
   of a [23,12] Golay codeword. */ 
{ 
  int i; 
  cw&=0x7fffffl; 
  for (i=1; i<=12; i++)  /* examine each data bit */ 
    { 
      if (cw & 1)        /* test data bit */ 
        cw^=POLY;        /* XOR polynomial */ 
      cw>>=1;            /* shift intermediate result */ 
    } 
  return(cw<<12);        /* value pairs with upper bits of cw */
}

static int weight(uint32_t cw) 
/* This function calculates the weight of 
   23 bit codeword cw. */ 
{ 
  int bits,k; 

  /* nibble weight table */ 
  const char wgt[16] = {0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4}; 

  bits=0; /* bit counter */ 
  k=0; 
  /* do all bits, six nibbles max */ 
  while ((k<6) && (cw)) 
    { 
      bits=bits+wgt[cw & 0xf]; 
      cw>>=4; 
      k++; 
    } 

  return(bits); 
} 

static uint32_t rotate_left(uint32_t cw, int n) 
/* This function rotates 23 bit codeword cw left by n bits. */ 
{ 
  int i; 

  if (n != 0) 
    { 
      for (i=1; i<=n; i++) 
        { 
          if ((cw & 0x400000l) != 0) 
            cw=(cw << 1) | 1; 
          else 
            cw<<=1; 
        } 
    } 

  return(cw & 0x7fffffl); 
} 

static uint32_t rotate_right(uint32_t cw, int n) 
/* This function rotates 23 bit codeword cw right by n bits. */ 
{ 
  int i; 

  if (n != 0) 
    { 
      for (i=1; i<=n; i++) 
        { 
          if ((cw & 1) != 0) 
            cw=(cw >> 1) | 0x400000l; 
          else 
            cw>>=1; 
        } 
    } 

  return(cw & 0x7fffffl); 
}

static uint32_t correct(uint32_t cw, int *errs) 
/* This function corrects Golay [23,12] codeword cw, returning the 
   corrected codeword. This function will produce the corrected codeword 
   for three or fewer errors. It will produce some other valid Golay 
   codeword for four or more errors, possibly not the intended 
   one. *errs is set to the number of bit errors corrected. */ 
{ 
  uint8_t 
    w;                /* current syndrome limit weight, 2 or 3 */ 
  uint32_t 
    mask;             /* mask for bit flipping */ 
  int 
    i,j;              /* index */ 
  uint32_t 
    s,                /* calculated syndrome */ 
    cwsaver;          /* saves initial value of cw */ 

  cwsaver=cw;         /* save */ 
  *errs=0; 
  w=3;                /* initial syndrome weight threshold */ 
  j=-1;               /* -1 = no trial bit flipping on first pass */ 
  mask=1; 
  while (j<23) /* flip each trial bit */ 
    { 
      if (j != -1) /* toggle a trial bit */ 
        { 
          if (j>0) /* restore last trial bit */ 
            { 
              cw=cwsaver ^ mask; 
              mask+=mask; /* point to next bit */ 
            } 
          cw=cwsaver ^ mask; /* flip next trial bit */ 
          w=2; /* lower the threshold while bit diddling */ 
        } 

      s=syndrome(cw); /* look for errors */ 
      if (s) /* errors exist */ 
        { 
          for (i=0; i<23; i++) /* check syndrome of each cyclic shift */ 
            { 
              if ((*errs=weight(s)) <= w) /* syndrome matches error pattern */
                { 
                  cw=cw ^ s;              /* remove errors */ 
                  cw=rotate_right(cw,i);  /* unrotate data */ 
                  return(s=cw); 
                } 
              else 
                { 
                  cw=rotate_left(cw,1);   /* rotate to next pattern */ 
                  s=syndrome(cw);         /* calc new syndrome */ 
                } 
            } 
          j++; /* toggle next trial bit */ 
        } 
      else 
        return(cw); /* return corrected codeword */ 
    } 

  return(cwsaver); /* return original if no corrections */ 
} /* correct */ 

int golay_decode(int *errs, const uint8_t *data)
/* This function decodes codeword *cw , error correction is attempted, 
   with *errs set to the number of bits corrected, and returning 0 if 
   no errors exist, or 1 if parity errors exist. */ 
{ 
  uint32_t cw = data[0] | (data[1]<<8) | (data[2]<<16);
  uint32_t parity_bit=cw & 0x800000l;
  cw&=~0x800000l;            /* remove parity bit for correction */
  cw=correct(cw, errs);     /* correct up to three bits */ 
  cw|=parity_bit;
  if (parity(cw))
    *errs++;
  return cw&0xFFF;
} /* decode */ 
