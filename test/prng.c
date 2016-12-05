#include <ccoin/crypto/prng.h> // for prng_get_random_bytes

#include <assert.h> // for assert
#include <math.h>   // for M_PI, fabs
#include <stdint.h> // for uint8_t
#include <stdio.h>  // for printf, fprintf, stderr
#include <stdlib.h> // for getenv

#define SAMPLE_SIZE_BYTES 524288 // Multple of buffer
#define BUFFER_SIZE 32

#ifdef M_PI
#define PI M_PI
#else
#define PI 3.14159265358979323846
#endif

extern double pochisq(const double ax, const int32_t df);
extern void rt_init(int binmode);
extern void rt_add(void *buf, int bufl);
extern void rt_end(double *r_ent, double *r_chisq, double *r_mean,
                   double *r_montepicalc, double *r_scc);

int main(int argc, char *argv[]) {

    if (!getenv("FORCE_PRNG_VERF")) {
        fprintf(stderr,
                "prng: Skipping PRNG verification test\n"
                "prng: Set FORCE_PRNG_VERF=1 to enable PRNG verification\n");
        return 77;
    }

    uint8_t ob[BUFFER_SIZE];
    unsigned long totalc = 0; /* Total character count */
    double montepi, chip, scc, ent, mean, chisq;

    /* Initialise for calculations */

    rt_init(0);

    /* Scan input and count character occurrences */

    for (totalc = 0; totalc < SAMPLE_SIZE_BYTES; totalc += BUFFER_SIZE) {
        assert(prng_get_random_bytes(ob, BUFFER_SIZE) >= 0);
        rt_add(ob, BUFFER_SIZE);
    }

    /* Complete calculation and return sequence metrics */

    rt_end(&ent, &chisq, &mean, &montepi, &scc);

    /* Calculate probability of observed distribution occurring from
    the results of the Chi-Square test */

    chip = pochisq(chisq, 255);

    /* Print calculated results */
    printf("Entropy:\n");
    printf("========\n");
    printf("Entropy = %f bits per byte.\n", ent);
    printf("\nOptimum compression would reduce the size\n");
    printf("of this %ld byte input by %d percent.\n\n", totalc,
           (int16_t)(100 * (8 - ent) / 8.0));

    // Optimum compression would reduction equal to 0%
    assert((int16_t)(100 * (8 - ent) / 8.0) == 0);

    printf("Chi-square Test:\n");
    printf("================\n");
    printf("Chi square distribution for %ld samples is %1.2f, and randomly\n",
           totalc, chisq);
    if (chip < 0.0001) {
        printf(
            "would exceed this value less than 0.01 percent of the times.\n\n");
    } else if (chip > 0.9999) {
        printf("would exceed this value more than than 99.99 percent of the "
               "times.\n\n");
    } else {
        printf("would exceed this value %1.2f percent of the times.\n\n",
               chip * 100);
    }

    // Chi-square test result between 10% and 90%
    assert(90 > (chip * 100));
    assert((chip * 100) > 10);

    printf("Arithmetic Mean:\n");
    printf("================\n");
    printf("Arithmetic mean value of data bytes is %1.4f (%.1f = random).\n\n",
           mean, 127.5);

    // Arithmetic Mean between 127 and 128
    assert(127.0 < mean);
    assert(mean < 128.0);

    printf("Monte Carlo Value for Pi:\n");
    printf("=========================\n");
    printf("Monte Carlo value for Pi is %1.9f (error %1.2f percent).\n\n",
           montepi, 100.0 * (fabs(PI - montepi) / PI));

    // Monte Carlo Value for Pi less than 0.5
    assert(0.5 > 100.0 * (fabs(PI - montepi) / PI));

    printf("Serial Correlation Coefficient:\n");
    printf("===============================\n");
    printf("Serial correlation coefficient is ");
    if (scc >= -99999) {
        printf("%1.6f (totally uncorrelated = 0.0).\n", scc);
    } else {
        printf("undefined (all values equal!).\n");
    }
    printf("\nSee https://www.fourmilab.ch/random/ for detailed description of "
           "output\n");

    // Serial Correlation Coefficient between -0.005 and 0.005
    assert(0.005 > scc);
    assert(scc > -0.005);

    return 0;
}
