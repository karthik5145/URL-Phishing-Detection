import numpy as np
import matplotlib.pyplot as plt
import pandas as pd

# Load the dataset
dataset = pd.read_csv('D:\URL_Phishing ML Project\dataset_phishing.csv')

# Data Preprocessing
print(dataset.isnull().sum())  # Check for missing values
print(dataset.info())         # Dataset information

# Encode the target variable
dataset['status'].replace(['legitimate', 'phishing'], [1, 0], inplace=True)

# Display initial rows and column names
print(dataset.head())
print(dataset.columns)

# Splitting data into features and labels
X = dataset.drop(columns=['status'])
y = dataset['status'].values

# Splitting dataset into training and test sets
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

# Feature Scaling
from sklearn.preprocessing import StandardScaler
sc = StandardScaler()
X_train = sc.fit_transform(X_train)
X_test = sc.transform(X_test)

# Support Vector Machine (SVM) Model
from sklearn.svm import SVC
classifier_svm = SVC(kernel='rbf', random_state=0, C=10, gamma=0.1)
classifier_svm.fit(X_train, y_train)
y_pred_svm = classifier_svm.predict(X_test)

# Evaluate SVM Model
from sklearn.metrics import confusion_matrix, accuracy_score
cm_svm = confusion_matrix(y_test, y_pred_svm)
acc_svm = accuracy_score(y_test, y_pred_svm)
print("SVM Confusion Matrix:")
print(cm_svm)
print(f"SVM Accuracy: {acc_svm}")

# K-Nearest Neighbors (KNN) Model
from sklearn.neighbors import KNeighborsClassifier
classifier_kn = KNeighborsClassifier(n_neighbors=7, metric='minkowski', p=2)
classifier_kn.fit(X_train, y_train)
y_pred_kn = classifier_kn.predict(X_test)

# Evaluate KNN Model
cm_kn = confusion_matrix(y_test, y_pred_kn)
acc_kn = accuracy_score(y_test, y_pred_kn)
print("KNN Confusion Matrix:")
print(cm_kn)
print(f"KNN Accuracy: {acc_kn}")

# Naive Bayes Model
from sklearn.naive_bayes import GaussianNB
classifier_nb = GaussianNB()
classifier_nb.fit(X_train, y_train)
y_pred_nb = classifier_nb.predict(X_test)

# Evaluate Naive Bayes Model
cm_nb = confusion_matrix(y_test, y_pred_nb)
acc_nb = accuracy_score(y_test, y_pred_nb)
print("Naive Bayes Confusion Matrix:")
print(cm_nb)
print(f"Naive Bayes Accuracy: {acc_nb}")

# Random Forest Model
from sklearn.ensemble import RandomForestClassifier
classifier_rf = RandomForestClassifier(n_estimators=100, criterion='entropy', random_state=0)
classifier_rf.fit(X_train, y_train)
y_pred_rf = classifier_rf.predict(X_test)

# Evaluate Random Forest Model
cm_rf = confusion_matrix(y_test, y_pred_rf)
acc_rf = accuracy_score(y_test, y_pred_rf)
print("Random Forest Confusion Matrix:")
print(cm_rf)
print(f"Random Forest Accuracy: {acc_rf}")

# Feature Importance Plot for Random Forest
plt.figure(figsize=(10, 8))
n_features = X_train.shape[1]
plt.barh(range(n_features), classifier_rf.feature_importances_, align='center')
plt.yticks(np.arange(n_features), dataset.columns[:-1])
plt.xlabel("Feature Importance")
plt.ylabel("Feature")
plt.title("Random Forest Feature Importance")
plt.show()

# Accuracy Visualization for Comparison
models = ['SVM', 'KNN', 'Naive Bayes', 'Random Forest']
accuracies = [acc_svm, acc_kn, acc_nb, acc_rf]

plt.figure(figsize=(8, 6))
plt.bar(models, accuracies, color=['blue', 'green', 'orange', 'red'])
plt.xlabel("Models")
plt.ylabel("Accuracy")
plt.title("Model Accuracy Comparison")
plt.ylim(0, 1)
plt.show()

# Hyperparameter Tuning for SVM
from sklearn.model_selection import GridSearchCV
parameters = {'C': [1, 10, 100], 'gamma': [0.01, 0.1, 1], 'kernel': ['rbf']}
grid_search = GridSearchCV(SVC(), parameters, cv=5, scoring='accuracy')
grid_search.fit(X_train, y_train)
print(f"Best Parameters for SVM: {grid_search.best_params_}")

# Final Model Selection (Random Forest for Feature Extraction)
url = "https://scikit-learn.org/stable/"
features = []

def length_url(url):
    features.append(len(url))
    parsed_url = urlparse(url)
    features.append(len(parsed_url.hostname))
    try:
        ipaddress.ip_address(parsed_url.netloc)
        ip = 1
    except:
        ip = 0
    features.append(ip)

length_url(url)

def https(url):
    features.append(0 if url.startswith("https://") else 1)

https(url)

def prop(url):
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('?'))
    features.append(url.count('='))
    features.append(url.count('_'))
    features.append(url.count('/'))
    features.append(url.count('www'))

prop(url)

def calculate_digits_ratio(url):
    digits = sum(c.isdigit() for c in url)
    features.append(digits / len(url))

calculate_digits_ratio(url)

def count_subdomains(url):
    features.append(len(urlparse(url).hostname.split('.')))

count_subdomains(url)

def count_redirections(url):
    features.append(len(requests.get(url, allow_redirects=True).history))

count_redirections(url)

def count_hyperlinks(url):
    soup = BeautifulSoup(requests.get(url).text, 'html.parser')
    features.append(len(soup.find_all('a')))

count_hyperlinks(url)

# Model Prediction
X_pred = sc.transform([features])
pred_rf = classifier_rf.predict(X_pred)
if pred_rf[0] == 0:
    print("PHISHING")
else:
    print("LEGITIMATE")

