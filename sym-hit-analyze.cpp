#include <stdint.h>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <assert.h>

using namespace std;
static const int BITS_PER_BYTE = 8;
struct Record
{
  int pid_;
  int tid_;
  uint64_t start_time_;
  uint64_t dur_;
  uint64_t start_time_thread_;
  uint64_t dur_thread_;
  uint64_t name_;
};

class Range
{
public:
  Range (uintptr_t base, size_t size, string &sym)
      : m_base (base), m_size (size), m_sym (sym)
  {
  }

  uintptr_t m_base;
  size_t m_size;
  string m_sym;
};

typedef std::vector<Range> RangeVector;

static bool
compare_range (const Range &r1, const Range &r2)
{
  return r1.m_base < r2.m_base;
}

static bool
compare (const Range &r, uintptr_t address)
{
  return r.m_base < address;
}

// input like: %x %x %s(no demangle symbol)

int
main (int argc, char **argv)
{
  if (argc != 3)
    {
      cerr << "usage : <data file> <sym file as comment>" << endl;
      return 1;
    }
  RangeVector range_vector;
  {
    ifstream sym_file (argv[2]);
    if (!sym_file)
      {
        cerr << "fails to open sym_file" << endl;
        return 1;
      }

    while (true)
      {
        string line;
        getline (sym_file, line);
        if (sym_file.eof ())
          {
            break;
          }
        uintptr_t base;
        size_t size;
        string sym;

        istringstream iss (line);
        iss >> hex >> base;
        iss >> hex >> size;
        iss >> sym;

        range_vector.push_back (Range (base, size, sym));
      }
  }

  sort (range_vector.begin (), range_vector.end (), compare_range);
  // handling the file to json.

  return 0;
}
