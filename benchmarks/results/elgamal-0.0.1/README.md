# Sinkhole-elgamal 0.0.1 benchmark results

See all benchmark results on the [criterion benchmark report](./report/index.html).

**Specs**: All benchmarks (client and server side) run on a commodity Apple 
machine with a 2.4 GHz Quad-Core Intel Core i5 (single core) and 16GB RAM. Note
that most of operations required to generate and run the storage query are CPU
bound.

## Summary for storage of size 2^20

### A. Time efficiency for storage of size 2^20

- **Query generation**:
  [137.05s](./db_setup_group/Setup%20DB%20size%202_20/report/index.html) (median)
- **DB setup**:
  [803.00ms](./db_setup_group/Setup%20DB%20size%202_20/report/index.html) (median)
- **Run query**:
  [121.13s](./run_query_group/Run%20query%20size%202_5/report/index.html) (median)

### B. Bandwidth requirements for storage of size 2^20

- **Query size**:  
The min size of a query if  `2^20 * CompressedRistretto.len()`. A byte
representation of a `CompressedRistretto` is 32 bytes. Thus, a compressed query
of 2^20 elements is 2^20 * 32 bytes = 33MB.

- **Result size**:
The result is encapsulated in a ciphertext == 32 bytes

