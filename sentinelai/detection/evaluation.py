"""M-1: reproducible binary-classification metrics and threshold selection."""
from __future__ import annotations
import numpy as np
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score


def evaluate_predictions(y_true, y_pred):
    y_true=np.asarray(y_true,dtype=int); y_pred=np.asarray(y_pred,dtype=int)
    if len(y_true)==0 or len(y_true)!=len(y_pred):
        raise ValueError("y_true and y_pred must have the same non-zero length")
    tn,fp,fn,tp=confusion_matrix(y_true,y_pred,labels=[0,1]).ravel()
    return {"precision":float(precision_score(y_true,y_pred,zero_division=0)),
            "recall":float(recall_score(y_true,y_pred,zero_division=0)),
            "f1":float(f1_score(y_true,y_pred,zero_division=0)),
            "false_positive_rate":float(fp/(fp+tn)) if tn+fp else 0.0,
            "accuracy":float(accuracy_score(y_true,y_pred)),
            "tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp)}


def choose_threshold(y_true, probabilities, candidates=None):
    """Tune only on validation labels. Maximise F1, then precision, then threshold."""
    if candidates is None: candidates=np.arange(.10,.91,.05)
    rows=[]
    for t in candidates:
        m=evaluate_predictions(y_true,(np.asarray(probabilities)>=float(t)).astype(int))
        rows.append({"threshold":float(t),**m})
    rows.sort(key=lambda r:(r["f1"],r["precision"],r["threshold"]),reverse=True)
    return rows[0]["threshold"], rows
