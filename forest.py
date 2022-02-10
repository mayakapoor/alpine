import re
import numpy as np
from datasketch import MinHash, MinHashLSHForest

def make_forest(data, perms):

    minhash = []

    for line in data:
        m = MinHash(num_perm=perms)
        for token in line:
            m.update(token.encode('utf-8'))
        minhash.append(m)

    forest = MinHashLSHForest(num_perm=perms)

    for i,m in enumerate(minhash):
        forest.add(i,m)

    forest.index()
    return forest

def query_forest(item, perms, num_results, forest):
    m = MinHash(num_perm=perms)
    lst = []
    lst.append(item)
    tokens = item.split()
    for token in tokens:
        m.update(token.encode('utf-8'))

    return np.array(forest.query(m, num_results))
