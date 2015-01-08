#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
//#include <lib/crypto/sha256.h>
#ifdef __linux__
#include <linux/rtc.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <errno.h>
#include <linux/random.h> 
#endif
#include "scryptenc.h"
#include "warn.h"
#include <crypto_scrypt.h>
#include <crypto_aesctr.h>
#include <errno.h>

#include <openssl/crypto.h>
#include <openssl/lhash.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>


int do_scrypt=1;
int gap;
FILE *outfile = NULL;
SHA256_CTX hashctx;


int timevaldiff(struct timeval *starttime, struct timeval *finishtime);
unsigned char count_ones(unsigned int num);
int debug=0;

int increment_until_gettimeofday(int us){
	// see how many rounds we can do in a fixed amount of time
	struct timeval now, then;
	int cycles=0;
	if(us>100) us/=100; // XXX should be documented better

	// this is *intentionally* a slow clock
	gettimeofday(&then, NULL);
	while(1){
	   cycles++;
	   gettimeofday(&now, NULL);
	   if(timevaldiff(&then, &now)>us) break;
	}
	//cycles&=7;
	return cycles;
}

int measure_usleep_with_clock_monotonic(int us){
	struct timespec now, then;
	int x;

	clock_gettime(CLOCK_MONOTONIC, &then);
	usleep(us);
	clock_gettime(CLOCK_MONOTONIC, &now);
	x= now.tv_nsec - then.tv_nsec;
	//x&=7;
	return x;
}

int measure_usleep_with_clock_realtime(int us){
	struct timespec now, then;
	int x;

	clock_gettime(CLOCK_REALTIME, &then);
	usleep(us);
	clock_gettime(CLOCK_REALTIME, &now);
	x= now.tv_nsec - then.tv_nsec;
	//x&=7;
	return x;
}

#if defined(__i386__) || defined(_amd64_) || defined(__x86_64__)
typedef unsigned long long ticks;
static __inline__ ticks getticks(void)
{
     unsigned a, d;
     asm("cpuid");
     asm volatile("rdtsc" : "=a" (a), "=d" (d));

     return (((ticks)a) | (((ticks)d) << 32));
}

int measure_usleep_with_rdtsc(int us){
   ticks now, then;
   long long ret;

   then = getticks();
   usleep(us);
   now = getticks();
   ret = now-then;
   //ret&=7;
   // intentionally casting back down to an int
   return (int) ret;
}
#endif



typedef struct {
   int *num;
   int sleep;
   int diff;
   int started;
   int stop;
} thread_rng_arg;

void *thread_twiddle(void *arg){
   thread_rng_arg *p = (thread_rng_arg *)arg;
   //struct timeval then, now;
   while(1){ 
      *(p->num) += p->diff; 
	  if(p->sleep) usleep(p->sleep);
	  p->started=1;
	  if(p->stop) { p->stop=2; return; }
   }
}

int read_thread_tugowar(unsigned char *buf, int len, int mode){
	pthread_t t1, t2;
	thread_rng_arg p1, p2;
	int i, bits=0;
	int raw_a,raw_b,a,b,merge;
	int swap=0;
	char zero=0;
	char one=1;

	memset(buf, 0, len);
	memset(&p1, 0, sizeof(thread_rng_arg));
	memset(&p2, 0, sizeof(thread_rng_arg));

	if(mode==0 || mode==2)  { p1.num = p2.num = calloc(4, 1);}
	if(mode==1)  { 
		p1.num = calloc(4,1);
		p2.num = calloc(4,1);
		}
	if(mode>2) { exit(255); }
	if(mode==2) { p2.started=1; p2.stop=2; }
	
	p1.diff=1; p2.diff=-1;
	
	pthread_create(&t1, NULL, thread_twiddle, &p1);
	if(mode==0 || mode==1) pthread_create(&t2, NULL, thread_twiddle, &p2);

	// don't start reading until both threads are spinning
	while(!p1.started || !p2.started) { usleep(10); }

	for(i=0; i<len;i++){
		while(bits<8){
			*p1.num=*p2.num=0;
			usleep(gap);
			if(mode==0 || mode==2) { merge = *p1.num; }
			if(mode==1) { merge = *p1.num + *p2.num; } // p2.diff is -1 so we add these, not that it *really* matters
			SHA256_Update(&hashctx, &merge, sizeof(int));
			if(outfile) fwrite(&merge, sizeof(int), 1, outfile);
			a = count_ones(merge) & 1;
			if(debug) fprintf(stderr, "bits=%i x=%i ", bits+i*8, merge);
			if(debug && mode==1) fprintf(stderr, "p1=%i p2=%i", *p1.num, *p2.num);
			if(debug) fprintf(stderr, "\n");
			usleep(gap);
			if(mode==0 || mode==2) { merge = *p1.num; }
			if(mode==1) { merge = *p1.num - *p2.num; }
			SHA256_Update(&hashctx, &merge, sizeof(int));
			if(outfile) fwrite(&merge, sizeof(int), 1, outfile);
			b = count_ones(merge) & 1;
			if(debug) fprintf(stderr, "bits=%i x=%i ", bits+i*8, merge);
			if(debug && mode==1) fprintf(stderr, "p1=%i p2=%i", *p1.num, *p2.num);
			if(debug) fprintf(stderr, "\n");
			if(a!=b) { a ? SHA256_Update(&hashctx, &zero, sizeof(zero)) : 
				           SHA256_Update(&hashctx, &one,  sizeof(one)); 
						   bits++;
			}
			if(outfile && a!=b) { a ? fwrite(&zero, sizeof(zero), 1, outfile) :
				                      fwrite(&one,  sizeof(one),  1, outfile);
			}
			//if(a!=b) { buf[i]<<=1; buf[i] |= swap?a:b; bits++; }
			//else { swap=!swap; }
			//fprintf(stdout, "huh? %u %u %u %u %u\n", a, b, *p1.num, i, buf[0]);
		}
		bits=0;
	}
	p1.stop=1;
	p2.stop=1;

	// don't return until both threads have stopped
	while(p1.stop<2 && p2.stop<2) { usleep(100); }
	SHA256_Final(buf, &hashctx);
	return len;
}

#ifdef __linux__
int rtc_fd=0;
int read_rtc(char *buf, int len, int mode){
	int i,bits=0;
	int raw_a, raw_b, a,b,swap,retval;
	unsigned long freq;
	long data;
	char zero=0;
	char one=1;
	struct timespec then, now;
	//ticks now,then;

	if(mode==7) { freq=128; }
	if(mode==8) { freq=8192; }

	if(rtc_fd==0){		
		rtc_fd = open("/dev/rtc0", O_RDONLY);
		retval = ioctl(rtc_fd, RTC_IRQP_SET, freq);
		if (retval == -1) {
				/* not all RTCs can change their periodic IRQ rate */
				if (errno == ENOTTY) {
						fprintf(stderr,
								"\n...Periodic IRQ rate is fixed\n");
				}
				perror("RTC_IRQP_SET ioctl");
				exit(errno);
		}
		/* Enable periodic interrupts */
		retval = ioctl(rtc_fd, RTC_PIE_ON, 0);
		if (retval == -1) {
				perror("RTC_PIE_ON ioctl");
				exit(errno);
		}
	}
	
	for(i=0; i<len;i++){
		while(bits<8){	
			clock_gettime(CLOCK_MONOTONIC, &then);
			//then=getticks();
			read(rtc_fd, &data, sizeof(unsigned long));
			clock_gettime(CLOCK_MONOTONIC, &now);
			//now=getticks();
			if(debug) fprintf(stderr, "bits=%i x=%lu\n", bits+i*8, now.tv_nsec - then.tv_nsec);
			a = count_ones(now.tv_nsec - then.tv_nsec) & 1;
			//a=count_ones(now-then)&1;

			clock_gettime(CLOCK_MONOTONIC, &then);
			//then=getticks();
			read(rtc_fd, &data, sizeof(unsigned long));
			//now=getticks();
			clock_gettime(CLOCK_MONOTONIC, &now);
			if(debug) fprintf(stderr, "bits=%i x=%lu\n", bits+i*8, now.tv_nsec - then.tv_nsec);
			b = (now.tv_nsec - then.tv_nsec) & 1;
			//b=(now-then)&1;

			//if(a!=b) { buf[i]<<=1; buf[i] |= swap?a:b; bits++; }
			//else { swap=!swap; }			
			SHA256_Update(&hashctx, &a, sizeof(int));
			if(outfile) fwrite(&a, sizeof(int), 1, outfile);
			SHA256_Update(&hashctx, &b, sizeof(int));
			if(outfile) fwrite(&b, sizeof(int), 1, outfile);
			a = count_ones(a) & 1;
			b = count_ones(b) & 1;
			// this is a modified von neumann debiasing -- we *always* hash in content, but we only accept bits
			// when von neumann is happy.  Just for consistency though we also hash in a 0 or 1.  More the
			// merrier.
			if(a!=b) { a ? SHA256_Update(&hashctx, &zero, sizeof(zero)) : 
				           SHA256_Update(&hashctx, &one,  sizeof(one)); 
						   bits++;
			}
			if(outfile && a!=b) { a ? fwrite(&zero, sizeof(zero), 1, outfile) :
				                      fwrite(&one,  sizeof(one),  1, outfile);
			}
		}
		bits=0;
	}
	//retval = ioctl(fd, RTC_PIE_OFF, 0);
	//close(fd);
	SHA256_Final(buf, &hashctx); // length is included in MD hardening, but doesn't make sense to add into outfile
	return len;
}
#endif

struct crypto_aesctr *aes_ctx = NULL;
unsigned char *stream_old=NULL;
unsigned char *stream_new=NULL;;
unsigned int stream_avail=0;

void cs_init(unsigned char *dk, unsigned int dklen){
   AES_KEY *key;
   key = calloc(sizeof(AES_KEY),1);
   if(dklen>sizeof(AES_KEY)) { exit(255); }
   memcpy(&key->rd_key, dk, dklen);
   key->rounds=14;
   aes_ctx = crypto_aesctr_init(key, 0);
}

#define WIDTH 1024
int cs_read(unsigned char *dst, unsigned int len){
   unsigned int count=len;
   unsigned int i=0;
   unsigned char *tmp;
   int to_copy=0;
   if(stream_old==NULL) stream_old = calloc(WIDTH, 1);
   if(stream_new==NULL) stream_new = calloc(WIDTH, 1);
   while(i<len){
      if(stream_avail==0) 
      {
         tmp=stream_old;
         stream_old=stream_new;
         stream_new=stream_old;
         crypto_aesctr_stream(aes_ctx, stream_old, stream_new, WIDTH);
         stream_avail+=WIDTH;
      }
      if(len-i<stream_avail){
         to_copy=(len-i);
         memcpy(dst+i, stream_new+(WIDTH-stream_avail), to_copy);
         stream_avail-=to_copy;
         i+=to_copy;
      } else {
         memcpy(dst+i, stream_new+(WIDTH-stream_avail), stream_avail);
         i+=stream_avail;
         stream_avail=0;
      }
   }
   return len;
}

int read_random(char *buf, int len, int mode){
	int i,bits=0;
	int (*random_generator)(int)=NULL;
	int raw_a,raw_b,a,b,swap;
	unsigned int N, r, p;
	unsigned char salt[32];
	unsigned char scrypt_aes[64];
	unsigned char kesha[32];
	char zero=0;
	char one=1;

	memset(buf, 0, len);

	// the thread readers require persistent state.  Isolate them.
	if(mode==0){ read_thread_tugowar(kesha, sizeof(kesha), 0); }
	if(mode==1){ read_thread_tugowar(kesha, sizeof(kesha), 1); }	
	if(mode==2){ read_thread_tugowar(kesha, sizeof(kesha), 2); }	
	// the simple generators just return an int, and can be called repeatedly.
	if(mode==3){ random_generator = increment_until_gettimeofday;}
	if(mode==4){ random_generator = measure_usleep_with_clock_monotonic; }
	if(mode==5){ random_generator = measure_usleep_with_clock_realtime; }
#if defined(__i386__) || defined(_amd64_) || defined(__x86_64__)
	if(mode==6){ random_generator = measure_usleep_with_rdtsc; }
#else
	fprintf(stderr, "RDTSC support is X86/X64 only.  ARM/MIPS is...sort of possible.\n");
    exit(202);
#endif
#ifdef __linux__
	if(mode==7){ read_rtc(kesha, sizeof(kesha), 7); } //we only want 256 bits
	if(mode==8){ read_rtc(kesha, sizeof(kesha), 8); }
#endif
#ifndef __linux__
   if(mode==7 || mode==8) {
   	fprintf(stderr, "RTC support is Linux only (for now)\n");
	exit(201);
   }
#endif   
	if(mode >8){ exit(254); }

	if(random_generator){
		for(i=0; i<32; i++){ // This explicitly means we want only 256 bits of entropy
			while(bits<8){
				raw_a = random_generator(gap);
				raw_b = random_generator(gap);
				SHA256_Update(&hashctx, &raw_a, sizeof(int));
				if(outfile) fwrite(&raw_a, sizeof(int), 1, outfile);
				if(debug) fprintf(stderr, "bits=%i x=%u\n", bits+i*8, raw_a);
				SHA256_Update(&hashctx, &raw_b, sizeof(int));
				if(outfile) fwrite(&raw_b, sizeof(int), 1, outfile);
				if(debug) fprintf(stderr, "bits=%i x=%u\n", bits+i*8, raw_b);
				a = count_ones(raw_a) & 1;
				b = count_ones(raw_b) & 1;
				if(a!=b) { a ? SHA256_Update(&hashctx, &zero, sizeof(zero)) : 
							   SHA256_Update(&hashctx, &one,  sizeof(one)); 
							   bits++;
				}
				if(outfile && a!=b) { a ? fwrite(&zero, sizeof(zero), 1, outfile) :
					                      fwrite(&one,  sizeof(one),  1, outfile);
				}
			}
			bits=0;
		}
		SHA256_Final(kesha, &hashctx);
	}
	
	N = 1<<15;	
	r = 8;	
	p = 1;
	// fixed salt is fine since the key is never (presumably) repeated
	memset(salt, 0, sizeof(salt));

	if(do_scrypt==1) { 
		crypto_scrypt(kesha, sizeof(kesha), salt, sizeof(salt), N, r, p, scrypt_aes, sizeof(scrypt_aes));
		cs_init(scrypt_aes, sizeof(scrypt_aes));
		}
	else {
		cs_init(kesha, sizeof(kesha));
		}

	cs_read(buf, len);	
	
	return len; //len;		
}



// utility functions
int timevaldiff(struct timeval *starttime, struct timeval *finishtime)
{
  int msec;
  msec=(finishtime->tv_sec-starttime->tv_sec)*1000;
  msec+=(finishtime->tv_usec-starttime->tv_usec)/1000;
  return msec;
}

unsigned char count_ones(unsigned int num){
   unsigned char i;
   unsigned char sum=0;
   for(i=0; i<sizeof(num)*8; i++){
      sum+=(num&1);
      num>>=1;
   }
   return sum;
}


#define VERSION "1.0"
void help(){
fprintf(stdout,
"dakarand %s: Highly Experimental Entropy Generator For Commodity Hardware\n\
Dan Kaminsky, Chief Scientist, DKH / dankaminsky.com / dan@doxpara.com \n\
Summary:\n\
    Any system with two clocks is not deterministic.  Even one part per\n\
    million of jitter equals a bit per megahertz per second.  Dakarand\n\
    is a framework to test whether these bits might be useful after all.\n\
    THIS CODE IS DESIGNED TO BE ATTACKED AND IS EXPECTED TO FAIL.  DO NOT\n\
    USE IT FOR ANYTHING EVEN REMOTELY IMPORTANT...yet.\n\
Options:\n\
    -v: Verbose -- show intermediate values, from which 1 bit is extracted\n\
    -m mode: Select entropy source.\n\
      0: Two Threads, One Int\n\
      1: Two Threads, Two Ints\n\
      2: One Thread,  One Int\n\
      3: Increment Until Gettimeofday\n\
      4: Measure usleep with CLOCK_MONOTONIC [default]\n\
      5: Measure usleep with CLOCK_REALTIME\n\
      6: Measure usleep with RDTSC\n\
      7: Measure RTC (128hz) with CLOCK_MONOTONIC  [LINUX ONLY]\n\
      8: Measure RTC (8192hz) with CLOCK_MONOTONIC [LINUX ONLY]\n\
    -r:  Update system entropy [LINUX ONLY]\n\
    -f format: Select output format\n\
      0: 16 hexadecimal bytes, comma delimited [default]\n\
      1: 4 integers from 0 to 2**32-1\n\
      2: Raw bytes\n\
    -o filename: Select output file\n\
    -l length: Select approximate number of output bytes\n\
    -g us: Microseconds between probes (default: 1000)\n\
    -d debugfile: File which will receive raw bits being hashed --\n\
                  attack this!\n\
    -s: Disable scrypt'ing of hashed entropy\n\
Credit:  This is based on Truerand from Matt Blaze and DP Mitchell '95-'96.\n\
", VERSION);
}


int main(int argc, char **argv){
	//unsigned char buf[32];
	unsigned char *buf;
	int i,j,c;
	int mode=4;
	int format=0;
	int len=32;
	int *ic;	
	int update_entropy=0;
	int err;
#ifdef __linux__
	int rndfd;
	struct rand_pool_info *output; 
#endif

	FILE *out = stdout;

	SHA256_Init(&hashctx);
	gap=1000;
	outfile=NULL;

	while((c=getopt(argc, argv, "m:f:o:vl:rg:d:s")) != -1){
		switch(c){
			case 'm':
				mode = atoi(optarg);
				break;
			case 'f':
				format = atoi(optarg);
				break;
			case 'o':
				if(strncmp(optarg, "-", 2)==0) { out = stdout; }
				else { out = fopen(optarg, "w"); }
				break;
			case 'v':
				debug=1;
				break;
			case 'l':
				len = atoi(optarg);
				if(len<sizeof(buf)) { fprintf(stdout, "length must be at least %u\n", (unsigned int) sizeof(buf)); exit(101); }
				break;
			case 'r':
				update_entropy=1;
				break;
			case 'g':
				gap = atoi(optarg);
				break;
			case 'd':
				outfile = fopen(optarg, "w");
				break;
			case 's':
				do_scrypt=0;
				break;
			default:
				help();
				exit(100);
				break;
				
		}
	}
	
	/*for(i=0; i<len; i+=sizeof(buf)){
		read_random(buf, sizeof(buf), mode);
		if(format==0) {
			for(j=0; j<sizeof(buf); j++) fprintf(out, "%2.2x, ", buf[j]);
			fprintf(stdout, "\n");
		}
		if(format==1) {
			for(j=0; j<sizeof(buf); j+=4){
				ic = (int *)(buf+j);
				fprintf(out, "%u\n", *ic);
			}
		}
		if(format==2) {
			fwrite(buf, sizeof(buf), 1, out);
			fflush(out);
		}	
	}*/
	buf = malloc(len);
	read_random(buf, len, mode);	
#ifdef __linux__
	if(update_entropy){
		int rndfd = open("/dev/random", O_WRONLY);
		output = malloc(sizeof(struct rand_pool_info) + len);
		output->buf_size = len;
		output->entropy_count = output->buf_size * 8;
		memcpy(output->buf, buf, len);
		err=ioctl(rndfd, RNDADDENTROPY, output);
		fprintf(stdout, "%u\n", err);
		free(output);
		close(rndfd);
	}
#endif
	if(format==0) {
		for(j=0; j<len; j++) fprintf(out, "%2.2x, ", buf[j]);
		fprintf(stdout, "\n");
	}
	if(format==1) {
		for(j=0; j<len; j+=4){
			ic = (int *)(buf+j);
			fprintf(out, "%u\n", *ic);
		}
	}
	if(format==2) {
		fwrite(buf, len, 1, out);
		fflush(out);
	}	
		
}

