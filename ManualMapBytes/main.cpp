#include "globals.h"

int main() {
	ManualMapper* mapper = new ManualMapper();
	mapper->setup("ragna4th.exe", "ragna4th.exe");
	mapper->load_dll();
	mapper->inject_dll();
	system("pause");
}