#ifndef BESS_LIB_AHO_CORASICK_
#define BESS_LIB_AHO_CORASICK_

#include <string>
#include <queue>
#include <vector>

int BuildMatchingMachine(const std::vector<std::string> words);

int FindNextState(int currentState, char nextInput);

std::vector<int> SearchWords(int k, std::string& text);

#endif // BESS_LIB_AHO_CORASICK_
