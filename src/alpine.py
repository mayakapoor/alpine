import re
import numpy as np
from collections import defaultdict
from datasketch import MinHash, MinHashLSHForest

class Alpine:
    def __init__(self, perms):
        self.my_forest = MinHashLSHForest(num_perm=perms)
        self.my_lookup_table = {}
        self.my_num_perms = perms
        self.my_curr_index = 0

    def add_bucket(self, data, label):
        minhash = []

        for i, row in data.iterrows():
            m = MinHash(num_perm=self.my_num_perms)
            for token in row.values.tolist():
                m.update(token.encode('utf-8'))
            minhash.append(m)

        for m in minhash:
            # add the hash with its index to the forest
            self.my_forest.add(self.my_curr_index,m)
            # add the index with label to the lookup table
            self.my_lookup_table[self.my_curr_index] = label
            self.my_curr_index += 1

    def finalize(self):
        self.my_forest.index()

    def query(self, tokens, num_results):
        m = MinHash(num_perm=self.my_num_perms)
        for token in tokens:
            m.update(str(token).encode('utf-8'))
        arr = np.array(self.my_forest.query(m, num_results))
        counts = defaultdict()
        for ret in arr:
            bucket = self.my_lookup_table[ret]
            if bucket in counts:
                counts[bucket] += 1
            else:
                counts[bucket] = 1
        return max(counts, key=counts.get)
