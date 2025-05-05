#include "entropy.h"

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>


double calculate_entropy (unsigned long* freq, unsigned long size) 
{
        int c;
        double entropy = 0.0;

        for (int i = 0; i < 256; i++) {
                if (freq[i] > 0) {
                        double p = (double)freq[i] / size;
                        entropy -= p * log2(p);
                }
        }

        return entropy;
}