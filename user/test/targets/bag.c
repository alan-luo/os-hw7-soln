#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
	char *pass = getpass("Top secret key: ");

	if (!*pass) {
		printf("Invalid pass (len must be > 0); abort\n");
		return 1;
	}

	char buf[100], buf_item[10];
	int poke_balls = 10, potions = 10, rare_candies = 10;

	for (;;) {
		printf("\n1: %d Poké Balls\n", poke_balls);
		printf("2: %d Potions\n", potions);
		printf("3: %d Rare Candies\n", rare_candies);
		printf("\nGive to: ");
		fflush(stdout);
		if (fgets(buf, sizeof(buf), stdin) == NULL)
			break;

		size_t len = strlen(buf);

		buf[len-1] = buf[len-1] == '\n' ? 0 : buf[len-1];
		printf("Which item (1-3): ");
		fflush(stdout);
		if (fgets(buf_item, sizeof(buf_item), stdin) == NULL)
			break;
		printf("\n");
		switch (atoi(buf_item)) {
		case 1:
			--poke_balls;
			printf("Gave 1 Poké Ball to \"%s\"\n", buf);
			break;
		case 2:
			--potions;
			printf("Gave 1 Potion to \"%s\"\n", buf);
			break;
		case 3:
			--rare_candies;
			printf("Gave 1 Rare Candy to \"%s\"\n", buf);
			break;
		default:
			printf("Invalid item.\n");
		}
	}
}
