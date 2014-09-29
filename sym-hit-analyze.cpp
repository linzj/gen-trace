#include <stdint.h>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <assert.h>

#include <string.h>

using namespace std;
static const int BITS_PER_BYTE = 8;
static bool zero_base = false;
struct Record
{
  int pid_;
  int tid_;
  uint64_t start_time_;
  uint64_t dur_;
  uint64_t name_;
};

class Range
{
public:
  Range (uintptr_t base, size_t size, string &sym)
      : m_base (base), m_size (size), m_sym (sym)
  {
  }

  uint64_t m_base;
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
compare (const Range &r, uint64_t address)
{
  return r.m_base < address;
}

// json write here

class io_exception : public exception
{
public:
  virtual const char *
  what () const throw ()
  {
    return "io_exception";
  }
};

class function_name_exception : public exception
{
public:
  virtual const char *
  what () const throw ()
  {
    return "function_name";
  }
};

static string
get_data_file_out_name (const char *name)
{
  const char *backslash = strrchr (name, '/');
  if (backslash != NULL)
    name = backslash + 1;
  string result (name);
  result.append (".json");
  return result;
}

static bool
read_a_record (Record &r, ifstream &data_file)
{
  data_file.read (reinterpret_cast<char *> (&r), sizeof (r));
  if (data_file.eof ())
    return true;
  if (data_file.gcount () != sizeof (r))
    throw io_exception ();
  return false;
}

static string
find_function_name (uint64_t base, const Record &r,
                    const RangeVector &range_vector)
{
  uint64_t bound = r.name_ - base;
  typedef RangeVector::const_iterator iterator;
  iterator i = lower_bound (range_vector.begin (), range_vector.end (), bound,
                            compare);
  if (i == range_vector.end ())
    return "Unknown function";
  if (i->m_base <= bound && i->m_base + i->m_size > bound)
    {
      return i->m_sym;
    }
  else
    return "Unknown function";
}

static void
handle_data_file (ifstream &data_file, ofstream &data_file_out,
                  const RangeVector &range_vector)
{
  Record r;
  read_a_record (r, data_file);
  uint64_t base = r.name_;
  if (zero_base)
    base = 0;
  // init the data_file_out
  data_file_out << "{\"traceEvents\": [";
  bool needComma = false;

  while (true)
    {
      if (read_a_record (r, data_file))
        {
          // end of file hit
          data_file_out << "]}";
          break;
        }
      Record *current = &r;
      string function_name = find_function_name (base, r, range_vector);
      if (!needComma)
        {
          needComma = true;
        }
      else
        {
          data_file_out << ",";
        }

      data_file_out << "{\"cat\":\""
                    << "profile"
                    << "\""
                    << ",\"pid\":" << r.pid_ << ",\"tid\":" << r.tid_
                    << ",\"ts\":" << r.start_time_ << ",\"ph\":\"X\""
                    << ",\"name\":\"" << function_name << "\""
                    << ",\"dur\":" << r.dur_ << "}";
    }
}

// input like: %x %x %s(no demangle symbol)

int
main (int argc, char **argv)
{
  if (argc < 3)
    {
      cerr << "usage : <data file> <sym file as comment>" << endl;
      return 1;
    }
  else if (argc > 3)
    {
      zero_base = true;
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
        getline (iss, sym);

        range_vector.push_back (Range (base, size, sym));
      }
  }

  sort (range_vector.begin (), range_vector.end (), compare_range);
  // handling the file to json.
  ifstream data_file (argv[1], ios_base::in | ios_base::binary);
  if (!data_file)
    {
      cerr << "fails to open data file" << endl;
      return 1;
    }
  string data_file_out_name = get_data_file_out_name (argv[1]);

  ofstream data_file_out (data_file_out_name.c_str ());
  if (!data_file_out)
    {
      cerr << "fails to open output file" << endl;
      return 1;
    }

  handle_data_file (data_file, data_file_out, range_vector);

  return 0;
}
