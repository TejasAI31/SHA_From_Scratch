#include <iostream>
#include "SHA.h"

vector<string> garbagestrings;

void createGarbageText(int num)
{
	srand(time(NULL));
	for (int i = 0; i < num; i++)
	{
		garbagestrings.push_back(to_string(rand()));
	}
}

void sampleSHA(int num)
{
	SHA hasher224("224");
	SHA hasher256("256");
	SHA hasher384("384");
	SHA hasher512("512");

	vector<SHA> hashers = { hasher224,hasher256,hasher384,hasher512 };
	vector<string> titles = { "V224","V256","V384","V512" };

	createGarbageText(num);

	for (int j = 0; j < hashers.size(); j++)
	{
		cout << titles[j] << endl;

		for (int i = 0; i < garbagestrings.size(); i++)
		{
			string generatedhash = hashers[j].hash(garbagestrings[i]);
			cout << "String:"<<garbagestrings[i] << " Hash:" << generatedhash << endl;
		}
		cout << endl;
	}
	garbagestrings.clear();
}

void customString()
{
	static SHA s224("224");
	static SHA s256("256");
	static SHA s384("384");
	static SHA s512("512");

	cout << "\nEnter String: ";
	string str;
	std::getline(std::cin>>std::ws, str);
	cout << "\nCHOOSE HASHER:\n";
	cout << "1) SHA224\n";
	cout << "2) SHA256\n";
	cout << "3) SHA384\n";
	cout << "4) SHA512\n";
	cout << "\nCHOOSE (1-4):";
	short int ch;
	cin >> ch;

	string out;
	switch (ch)
	{
	case 1:
		out = s224.hash(str);
		break;
	case 2:
		out = s256.hash(str);
		break;
	case 3:
		out = s384.hash(str);
		break;
	case 4:
		out = s512.hash(str);
		break;
	}
	cout << "HASH: " << out << "\n";
	cout << "LENGTH: " << out.length()*4 << " Bits\n";
	cout << endl;
}

short int choiceScreen()
{
	cout << "Hash Custom String or Sample All Hashers? :\n";
	cout << "1: Custom String\n";
	cout << "2: Sample All Hashers\n";
	cout << "Other: Exit\n";
	cout << "Enter Choice (1/2): ";
	short int choice;
	cin >> choice;
	return choice;
}

int main()
{
	short int ch = choiceScreen();
	while (ch == 1 || ch == 2)
	{
		switch (ch)
		{
		case 2:
			sampleSHA(10);
			break;
		case 1:
			customString();
			break;
		}
		ch = choiceScreen();
	}
	return 0;
}