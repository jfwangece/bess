#include "aho_corasick.h"

#include <string.h>

namespace {
// Max number of states in the matching machine.
// Should be equal to the sum of the length of all keywords.
const int MAX_STATES = 20000;

// Number of characters in the alphabet.
const int MAX_CHARS = '~' - ' ' + 1;

// Output for each state, as a bitwise mask.
// Bit i in this mask is on if the keyword with index i appears
// when the machine enters this state.
int out[MAX_STATES + 1] = {0};

// Used internally in the algorithm
int f[MAX_STATES + 1] = {0}; // Failure function

int g[MAX_STATES + 1][MAX_CHARS + 1] = {0}; // Goto function, or -1 if fail.
} // namespace

int BuildMatchingMachine(const std::vector<std::string> words) {
  // Init
  memset(out, 0, sizeof out);
  memset(f, -1, sizeof f);
  memset(g, -1, sizeof g);

  int states = 1;
  int k = words.size();

  // Construct values for goto function, i.e., fill g[][]
  // This is same as building a Trie for arr[]
  for (int i = 0; i < k; ++i)
  {
    const std::string &word = words[i];
    int currentState = 0;
    // Insert all characters of current word in |word|
    for (int j = 0; j < int(word.size()); ++j) {
      int ch = word[j] - ' ';
      if (g[currentState][ch] == -1) {
          g[currentState][ch] = states++;
      }

      currentState = g[currentState][ch];
    }
    // There's a match of words[i] at node currentState.
    out[currentState] |= (1 << i);
  }

  // For all characters which don't have an edge from
  // root (or state 0) in Trie, add a goto edge to state
  // 0 itself
  for (int ch = 0; ch < MAX_CHARS; ++ch) {
    if (g[0][ch] == -1) {
        g[0][ch] = 0;
    }
  }

  // Now, let's build the failure function
  std::queue<int> q;
  // Iterate over every possible input
  for (int ch = 0; ch < MAX_CHARS; ++ch) {
    // All nodes of depth 1 have failure function value as 0.
    if (g[0][ch] != -1 && g[0][ch] != 0) {
        f[g[0][ch]] = 0;
        q.push(g[0][ch]);
    }
  }

  // Now std::queue has states 1 and 3
  while (q.size() > 0) {
    // Remove the front state from std::queue
    int state = q.front();
    q.pop();

    // For the removed state, find failure function for
    // all those characters for which goto function is
    // not defined.
    for (int ch = 0; ch < MAX_CHARS; ++ch) {
      // If goto function is defined for character 'ch' and 'state'
      if (g[state][ch] != -1) {
        // Find failure state of removed state
        int failure = f[state];

        // Find the deepest node labeled by proper suffix of
        // std::string from root to current state.
        while (g[failure][ch] == -1) {
            failure = f[failure];
        }
        failure = g[failure][ch];
        f[g[state][ch]] = failure;
        out[g[state][ch]] |= out[failure];

        // Insert the next level node (of Trie) in std::queue
        q.push(g[state][ch]);
      }
    }
  }

  return states;
}

// Returns the next state the machine will transition to using goto
// and failure functions.
// currentState - The current state of the machine. Must be between
//                0 and the number of states - 1, inclusive.
// nextInput - The next character that enters into the machine.
int FindNextState(int currentState, char nextInput) {
  int answer = currentState;
  int ch = nextInput - ' ';

  // If goto is not defined, use failure function
  while (g[answer][ch] == -1) {
    answer = f[answer];
  }

  return g[answer][ch];
}

// This function finds all occurrences of all array words
// in text.
std::vector<int> SearchWords(int k, std::string& text) {
  std::vector<int> results;

  // Initialize current state
  int currentState = 0;

  // Traverse the text through the nuilt machine to find
  // all occurrences of words in arr[]
  char c;
  for (int i = 0; i < int(text.size()); ++i) {
    c = text[i];
    if (c < ' ' || 'c' > '~') {
      c = ' ';
    }
    currentState = FindNextState(currentState, c);

    // If match not found, move to next state
    if (out[currentState] == 0) {
      continue;
    }

    // Match found, print all matching words of arr[]
    // using output function.
    for (int j = 0; j < k; ++j) {
      if (out[currentState] & (1 << j)) {
        results.push_back(i);
      }
    }
  }

  return results;
}
