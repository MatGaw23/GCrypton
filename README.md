# GCrypton

A project to deep dive into cryptography algorithms.

## Requirements

- CMake 3.14 or higher
- C++20 compliant compiler
- Catch2 (for testing)

## Building

```bash
# Clone the repository
git clone https://github.com/MatGaw23/GCrypton.git
cd GCrypton

# Create a build directory
mkdir build && cd build

# Configure and build
cmake ..
cmake --build .

# Run tests
ctest
```

## Project Structure

- `src/`: Contains the source code for the project
- `tests/`: Unit tests using Catch2
- `cmake/`: CMake modules and utilities

## License

This project is licensed under the MIT - see the LICENSE file for details.
