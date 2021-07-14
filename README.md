# Fluffy
Fluffy is a multi-transaction differential fuzzer for finding consensus bugs in Ethereum. First, Fluffy mutates and executes multi-transaction test cases to find consensus bugs which cannot be found using existing fuzzers for Ethereum. Second, Fluffy uses multiple existing Ethereum clients that independently implement the specification as cross-referencing oracles. Compared to a state-of-the-art fuzzer, Fluffy improves the fuzzing throughput by 510× and the code coverage by 2.7× with various optimizations: in-process fuzzing, fuzzing harnesses for Ethereum clients, and semantic-aware mutation that reduces erroneous test cases. 

The blockchain state model of existing Ethereum fuzzers falls short to cover the full search space for finding consensus bugs. The full search space consists of the set of possible client program states, which are the values of program variables of Ethereum clients that can be reached after executing Ethereum transactions. For each pre-transaction blockchain state (e.g., Account A has 0 ETH), the blockchain state model can cover only a single pre-transaction program state (e.g., account_a = { ETH: 0, deleted: false}). Consequently, existing fuzzers fail to test other possible pre-transaction program states (e.g., account_a = { ETH: 3, deleted: true}) that represent the same blockchain state. This leads existing fuzzers to miss consensus bugs which are triggered only when a transaction is applied to such other pre-transaction program states.

To fully cover the search space for finding consensus bugs, we propose to model an Ethereum client as a client program state model, in which the client program state is transitioned by a transaction. Based on this model, in each fuzzing itera- tion, we generate and execute a sequence of multiple transac- tions that transition an initial client program state. This allows us to indirectly generate various intermediate pre-transaction program states, which can be reached after executing transac- tions and can lead to the discovery of new consensus bugs.

Fluffy found two new consensus bugs, shallow copy bug ([CVE-2020-26241](https://nvd.nist.gov/vuln/detail/CVE-2020-26241)) and tranfer-after-destruct bug, in the most popular Geth Ethereum client which were exploitable on the live Ethereum mainnet. Four months after we reported the bugs to Geth developers, one of the bugs was triggered on the mainnet, and caused nodes using a stale version of Geth to hard fork the Ethereum blockchain. The blockchain community considers this hard fork the greatest challenge since the infamous 2016 DAO hack. 

* Code coverage and throughput
![스크린샷, 2021-06-29 14-19-31](https://user-images.githubusercontent.com/4114572/123741463-0e106d00-d8e5-11eb-94d5-722e38c9030f.png)

# Version

This version of Fluffy tests OpenEthereum v3.0.0 and Geth v1.9.14.

# Quickstart

```bash
sudo docker build -t fuzzer .
```

# Publication

Youngseok Yang, Taesoo Kim, Byung-Gon Chun. Finding Consensus Bugs in Ethereum via Multi-transaction Differential Fuzzing. OSDI 2021.

# Troubleshooting
Create an issue for questions and bug reports.

# Contribution
We welcome your contributions to Fluffy! We aim to create an open-source project that is contributed by the open-source community. For general discussions about development, please refer to the issues. To contact us, please send an email to fluffy@spl.snu.ac.kr.

# License
[Apache-2.0 License](https://github.com/snuspl/fluffy/blob/main/LICENSE)
