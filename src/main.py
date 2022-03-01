from alpine import Alpine
import time
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report,confusion_matrix ,ConfusionMatrixDisplay, cohen_kappa_score
from argparse import ArgumentParser
import matplotlib.pyplot as plt
import glob
import os
import seaborn as sns
import statistics
from imblearn.under_sampling import RandomUnderSampler

def extract_hash_values(df):
    return df[["src_port","dst_port","t_proto","dsfield","ip_flags","length","d_proto"]]

if __name__ == "__main__":
    parser = ArgumentParser(description="Process pcap file and integer data.")
    parser.add_argument("-dataFolder", help="The data root folder.")
    parser.add_argument("-classType", help="The classification type.")
    args = parser.parse_args()
    if args.classType not in ['application','traffic_type','arc','d_proto']:
        args.classType = 'application'
        print("The specified class type not found hence used default application class type")
    os.chdir(args.dataFolder)
    path = os.getcwd()
    list_X = []
    list_y =[]
    for root,dirs,files in os.walk(path):
        csv_files = glob.glob(os.path.join(root, "*.csv"))
        for f in csv_files:
            data = pd.read_csv(f, delimiter=",", dtype=str)
            data.dropna(inplace=True)
            # data = data.sample(100, random_state=4, replace=True)
            #print(data)
            data_X = extract_hash_values(data)
            data_y = data[[args.classType]]
            list_X.append(data_X)
            list_y.append(data_y)

    X = pd.concat(list_X, ignore_index=True)
    y = pd.concat(list_y, ignore_index=True)
    if (args.classType == "application"):
        y[args.classType] = y[args.classType].replace(["icq", "aim"], "pidgin")
        y[args.classType] = y[args.classType].replace(["sftp", "ftps"], "ftp")
    if (args.classType == "traffic_type"):
        y[args.classType] = y[args.classType].replace(["audio", "video"], "voip")
    print(len(X))
    print("Data count after sampling " , len(y))
    rus = RandomUnderSampler(random_state=888)
    X, y = rus.fit_resample(X, y)
    print("Data count after sampling " , len(y))


    # fig, ax = plt.subplots(figsize=(12, 12))
    # sns.countplot(x=args.classType,data = y,ax=ax,palette = 'CMRmap')
    # plt.show()
    # plt.savefig('../../images/class_distribution_{}.png'.format(args.classType))

    # need to do this for all the data, and for each of the three label types
    # aim_filename = r"aimchatvpn0.csv"
    # thunderbird_filename = r"thunderbirdemailvpn0.csv"
    # thunderbird = pd.read_csv(thunderbird_filename, delimiter=",", dtype=str)
    # print(thunderbird)

    # skype_filename = r"skypechatvpn0.csv"
    # skype = pd.read_csv(skype_filename, delimiter=",", dtype=str)
    # print(skype)

    # aim_x = extract_hash_values(aim)
    # thunderbird_x = extract_hash_values(thunderbird)
    # skype_x = extract_hash_values(skype)
    # aim_y = aim[["application"]]
    # thunderbird_y = thunderbird[["application"]]
    # skype_y = skype[["application"]]


    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.4, random_state=4, stratify=y)

    forest = Alpine(128)

    print("training phase...")
    labels = y_train[args.classType].unique()
    print(labels)
    start = time.time()

    for label in labels:
        curr = X_train.loc[y_train.loc[y_train[args.classType] == label].index.tolist()]
        forest.add_bucket(curr, label)
    # curr = x_train.loc[y_train.loc[y_train['application'] == "aim"].index.tolist()]
    # forest.add_bucket(curr, "aim")
    # curr = x_train.loc[y_train.loc[y_train['application'] == "skype"].index.tolist()]
    # forest.add_bucket(curr, "skype")
    print("training time in seconds: " + str(time.time() - start))

    forest.finalize()
    num_votes = 10
    y_pred = []
    length_per_sec = 0

    print("testing phase...")
    throughput = []
    classification_time = []
    start = time.time()
    throughput_start = time.time()
    for i, row in X_test.iterrows():
        y_pred.append(forest.query(row.values.tolist(), num_votes))
        length_per_sec += int(row["length"])
        if (time.time() - throughput_start) > 1:
            throughput.append(length_per_sec)
            throughput_start = time.time()
            length_per_sec = 0
    end = time.time()
    print("ms per classification: " + str((((end-start)/len(y_test))*1000)))
    print("throughput: " + str(statistics.mean(throughput)))
    print("number of test samples: " + str(len(y_test)))
    print("accuracy: " + str(accuracy_score(y_pred, y_test)))
    print("cohen kappa score: " + str(cohen_kappa_score(y_test, y_pred)))
    print("classification report: \n"+ classification_report(y_test, y_pred))
    cm = confusion_matrix(y_test[args.classType].tolist(), y_pred)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=labels)
    fig, ax = plt.subplots(figsize=(15, 15))
    disp.plot(ax=ax)
    plt.show()
    plt.savefig('../../images/confusion_matrix_{}.png'.format(args.classType))
    
  
