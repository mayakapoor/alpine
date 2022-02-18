import re
import numpy as np
from collections import defaultdict
from datasketch import MinHash, MinHashLSHForest

class Alpine:
    def __init__(self, perms):
        self.my_forest = MinHashLSHForest(num_perm=perms)
        self.my_lookup_table = {}
        self.my_num_perms = perms

    def add_bucket(self, data, label):
        minhash = []

        for line in data:
            m = MinHash(num_perm=self.my_num_perms)
            for token in line:
                m.update(token.encode('utf-8'))
            minhash.append(m)

        for i,m in enumerate(minhash):
            # add the hash with its index to the forest
            self.my_forest.add(i,m)
            # add the index with label to the lookup table
            self.my_lookup_table[i] = label

    def finalize(self):
        self.my_forest.index()

    def query(self, item, num_results):
        m = MinHash(num_perm=self.my_num_perms)
        lst = []
        lst.append(item)
        tokens = item.split()
        for token in tokens:
            m.update(token.encode('utf-8'))
        arr = np.array(self.my_forest.query(m, num_results))
        counts = defaultdict()
        for ret in arr:
            bucket = self.my_lookup_table[ret]
            if bucket in counts:
                counts[bucket] += 1
            else:
                counts[bucket] = 1
        return max(counts, key=counts.get)
