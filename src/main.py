from alpine import Alpine
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

def extract_hash_values(df):
    return df[["src_ip","dst_ip","src_port","dst_port","t_proto","dsfield","ip_flags","length","d_proto"]]

#need to do this for all the data, and for each of the three label types
aim_filename = r"aimchatvpn0.csv"
aim = pd.read_csv(aim_filename, delimiter=",", dtype=str)
print(aim)

thunderbird_filename = r"thunderbirdemailvpn0.csv"
thunderbird = pd.read_csv(thunderbird_filename, delimiter=",", dtype=str)
print(thunderbird)

aim_x = extract_hash_values(aim)
thunderbird_x = extract_hash_values(thunderbird)
aim_y = aim[["application"]]
thunderbird_y = thunderbird[["application"]]
x = pd.concat([aim_x, thunderbird_x], ignore_index=True)
y = pd.concat([aim_y, thunderbird_y], ignore_index=True)
print(len(x))
print(len(y))

x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.4, random_state=4, stratify=y)

forest = Alpine(128)

curr = x_train.loc[y_train.loc[y_train['application'] == "thunderbird"].index.tolist()]
forest.add_bucket(curr, "thunderbird")
curr = x_train.loc[y_train.loc[y_train['application'] == "aim"].index.tolist()]
forest.add_bucket(curr, "aim")

forest.finalize()
num_votes = 10
y_pred = []

print("testing phase...")

for i, row in x_test.iterrows():
    y_pred.append(forest.query(row.values.tolist(), num_votes))
print("number of test samples: " + str(len(y_test)))
print("accuracy: " + str(accuracy_score(y_pred, y_test)))
