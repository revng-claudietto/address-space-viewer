/* A program whose only purpose is to have an interesting address space.
 *
 * Each step is one thing a process can do to its own memory, in the order
 * that makes the map easiest to follow: reserve, commit, protect, grow,
 * move, name, share, release.  Nothing here is clever -- the point is that
 * every one of these is a syscall the recorder sees, and every one of them
 * moves a box on the screen.
 *
 * Build with: cc -O0 -g -o demo demo.c
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif
#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

#define PAGES(n) ((size_t)(n) * 4096)

static void say(const char *what)
{
	printf("%s\n", what);
	fflush(stdout);
}

/* A hole reserved with no access at all, the way a loader books room for a
   library before it knows what goes in it. */
static void *reserve(size_t length)
{
	void *at = mmap(NULL, length, PROT_NONE,
	                MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

	if (at == MAP_FAILED) {
		perror("mmap reserve");
		exit(1);
	}
	return at;
}

int main(void)
{
	say("reserve 64 pages with no access");
	char *arena = reserve(PAGES(64));

	say("commit the middle of it, read-write");
	if (mprotect(arena + PAGES(16), PAGES(16), PROT_READ | PROT_WRITE)) {
		perror("mprotect commit");
		return 1;
	}
	memset(arena + PAGES(16), 0x5a, PAGES(16));

	say("name the committed pages");
	prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, arena + PAGES(16), PAGES(16),
	      "demo arena");

	say("turn one page of it into code");
	if (mprotect(arena + PAGES(20), PAGES(1), PROT_READ | PROT_EXEC)) {
		perror("mprotect exec");
		return 1;
	}

	say("map this program's own binary, read-only");
	int self = open("/proc/self/exe", O_RDONLY);
	if (self < 0) {
		perror("open /proc/self/exe");
		return 1;
	}
	void *image = mmap(NULL, PAGES(8), PROT_READ, MAP_PRIVATE, self, 0);
	if (image == MAP_FAILED) {
		perror("mmap self");
		return 1;
	}
	close(self);

	say("map a page shared, and write to it");
	char *shared = mmap(NULL, PAGES(1), PROT_READ | PROT_WRITE,
	                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED) {
		perror("mmap shared");
		return 1;
	}
	strcpy(shared, "written before the fork");

	say("grow the heap, well past what malloc keeps in hand");
	char *big = malloc(4 << 20);
	if (!big) {
		perror("malloc");
		return 1;
	}
	memset(big, 1, 4 << 20);

	/* Growing in place only works if the next pages are free, so take them
	   and give them straight back rather than hoping. */
	say("grow a mapping in place");
	char *rope = mmap(NULL, PAGES(32), PROT_READ | PROT_WRITE,
	                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (rope == MAP_FAILED) {
		perror("mmap rope");
		return 1;
	}
	if (munmap(rope + PAGES(4), PAGES(28))) {
		perror("munmap tail");
		return 1;
	}
	if (mremap(rope, PAGES(4), PAGES(32), 0) == MAP_FAILED) {
		perror("mremap in place");
		return 1;
	}

	say("move a mapping somewhere else entirely");
	char *moved = mmap(NULL, PAGES(8), PROT_READ | PROT_WRITE,
	                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (moved == MAP_FAILED) {
		perror("mmap moved");
		return 1;
	}
	strcpy(moved, "the bytes do not move, the page tables do");
	moved = mremap(moved, PAGES(8), PAGES(16), MREMAP_MAYMOVE);
	if (moved == MAP_FAILED) {
		perror("mremap");
		return 1;
	}

	say("fork: the child gets a copy of all of it");
	pid_t child = fork();
	if (child == 0) {
		/* A private mapping of its own, in a space that is now separate. */
		void *mine = mmap(NULL, PAGES(24), PROT_READ | PROT_WRITE,
		                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (mine != MAP_FAILED)
			memset(mine, 7, PAGES(24));
		printf("child sees: %s\n", shared);
		fflush(stdout);
		_exit(0);
	}
	if (child < 0) {
		perror("fork");
		return 1;
	}
	waitpid(child, NULL, 0);

	say("release the middle of the arena, leaving a hole");
	if (munmap(arena + PAGES(24), PAGES(8))) {
		perror("munmap hole");
		return 1;
	}

	say("release everything else");
	munmap(image, PAGES(8));
	munmap(shared, PAGES(1));
	munmap(moved, PAGES(16));
	munmap(rope, PAGES(32));
	free(big);

	say("done");
	return 0;
}
