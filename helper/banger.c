int main() {
	char *str = "Hello, World!";
	char str2[] = "Salut, Monde!";
	const char *str3 = "Hola, Mundo!";
	const char str4[] = "Ciao, Mondo!";
	const char str5[14] = "Hallo, Welt!";
	char str6[14] = "Hej, Verden!";
	char const *str7 = "Hei, Maailma!";
	char const str8[] = "Hej, Världen!";
	char const str9[14] = "Hej, Verden!";

	const char* str10[] = {"123", "456", "789"};
	char* str15[] = {"111", "222", "333"};

	static char str11[] = "yo les potes";
	static char *str12 = "hey friends";
	static const char str13[] = "salut les amis";
	static const char *str14 = "hola amigos";

	return 0;
}
