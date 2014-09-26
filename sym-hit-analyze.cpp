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

class Range {
public:
    Range(uintptr_t base, size_t size, string& sym)
        : m_base(base)
        , m_size(size)
        , m_sym(sym)
    {
    }

    uintptr_t m_base;
    size_t m_size;
    string m_sym;
};

typedef std::vector<Range> RangeVector;

static bool compare_range(const Range& r1, const Range& r2)
{
    return r1.m_base < r2.m_base;
}

static bool compare(const Range& r, uintptr_t address)
{
    return r.m_base < address;
}

// input like: %x %x %s(no demangle symbol)

int main(int argc, char** argv)
{
    if (argc != 3) {
        cerr << "usage : <to_bitmap> <sym file as comment>" << endl;
        return 1;
    }
    RangeVector range_vector;
    {
        ifstream sym_file(argv[2]);
        if (!sym_file) {
            cerr << "fails to open sym_file" << endl;
            return 1;
        }

        while (true) {
            string line;
            getline(sym_file, line);
            if (sym_file.eof()) {
                break;
            }
            uintptr_t base;
            size_t size;
            string sym;

            istringstream iss(line);
            iss >> hex >> base;
            iss >> hex >> size;
            iss >> sym;

            range_vector.push_back(Range(base, size, sym));
        }
    }

    sort(range_vector.begin(), range_vector.end(), compare_range);
    vector<char> to_bitmap;
    {
        ifstream to_bitmap_file(argv[1], ios::binary | ios::in);
        if (!to_bitmap_file) {
            cerr << "fails to open to_bitmap" << endl;
            return 1;
        }
        std::copy(std::istreambuf_iterator<char>(to_bitmap_file),
                  std::istreambuf_iterator<char>(),
                  std::back_inserter(to_bitmap));
    }

    typedef vector<char>::const_iterator to_bitmap_iterator;
    uintptr_t address = 0;
    size_t total = 0U;
    for (to_bitmap_iterator i = to_bitmap.begin();
         i != to_bitmap.end();
         ++i, address += 8) {
        char val = *i;
        for (int j = 0; j < BITS_PER_BYTE; ++j) {
            int num = 1 << j;
            if (val & num) {
                uintptr_t _address = address + j;
                RangeVector::const_iterator lower = lower_bound(range_vector.begin(), range_vector.end(), _address, compare);
                assert(lower->m_base >= _address);
                if (lower->m_base != _address)
                    --lower;
                if ((lower->m_base <= _address) && ((uintptr_t)(lower->m_base + lower->m_size) >= _address)) {
                    cout << lower->m_sym << endl;
                    total++;
                }
            }
        }
    }
    // cout << "total :" << total << "; size of range_vector : " << range_vector.size() << "; end address : " << hex << address << endl;
    return 0;
}
