#!/usr/bin/env python3

import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
import json

def prio_to_weight(prio: int) -> int:
    """
    Convert kernel static priority (100–139) to a cgroup weight (1–10000).
    Implements:
        weight = sched_prio_to_weight[prio - MAX_RT_PRIO]
        cg_weight = clamp(round(weight * 100 / 1024), 1, 10000)
    """

    MAX_RT_PRIO = 100
    CGROUP_WEIGHT_MIN = 1
    CGROUP_WEIGHT_DFL = 100
    CGROUP_WEIGHT_MAX = 10000

    # Kernel's sched_prio_to_weight table (from kernel/sched/core.c)
    sched_prio_to_weight = [
        88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916,
        9548, 7620, 6100, 4904, 3906, 3121, 2501, 1991, 1586, 1277,
        1024, 820, 655, 526, 423, 335, 272, 215, 172, 137,
        110, 87, 70, 56, 45, 36, 29, 23, 18, 15,
    ]

    idx = prio - MAX_RT_PRIO
    if idx < 0 or idx >= len(sched_prio_to_weight):
        return CGROUP_WEIGHT_DFL

    weight = sched_prio_to_weight[idx]

    # Match kernel logic: DIV_ROUND_CLOSEST_ULL(weight * 100, 1024)
    cg_weight = round(weight * CGROUP_WEIGHT_DFL / 1024)
    cg_weight = max(CGROUP_WEIGHT_MIN, min(CGROUP_WEIGHT_MAX, cg_weight))
    return cg_weight

# =========================
# Load and preprocess trace
# =========================
df = pd.read_csv("trace.csv")

# Encode task names (string → integer)
enc_comm = LabelEncoder()
df["comm_enc"] = enc_comm.fit_transform(df["prev_comm"])

# Convert kernel priority to cgroup-like weight
df["weight"] = df["prio"].apply(prio_to_weight)

# Features: [encoded task name, priority]
X = df[["comm_enc", "weight"]].values
# Target: timeslice (continuous value)
y = df["timeslice"].values

# Convert to tensors
X_tensor = torch.tensor(X, dtype=torch.float32)
y_tensor = torch.tensor(y, dtype=torch.float32).view(-1, 1)

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X_tensor, y_tensor, test_size=0.2, random_state=42
)

# Device setup
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")

# =========================
# Model definition
# =========================
# Regression model: input=2 (comm_enc + prio), output=1 (predicted timeslice)
model = nn.Sequential(
    nn.Linear(2, 64),
    nn.ReLU(),
    nn.Linear(64, 64),
    nn.ReLU(),
    nn.Linear(64, 1)  # regression output
).to(device)

# Loss and optimizer
criterion = nn.MSELoss()
optimizer = optim.Adam(model.parameters(), lr=0.001)

# =========================
# Training loop
# =========================
for epoch in range(200):
    model.train()
    optimizer.zero_grad()
    outputs = model(X_train.to(device))
    loss = criterion(outputs, y_train.to(device))
    loss.backward()
    optimizer.step()

    if epoch % 20 == 0:
        model.eval()
        with torch.no_grad():
            test_outputs = model(X_test.to(device))
            test_loss = criterion(test_outputs, y_test.to(device))
            print(f"Epoch {epoch:03d}: Train MSE={loss.item():.4f}, Test MSE={test_loss.item():.4f}")

# =========================
# Save encoder + model
# =========================
# Save label encoder mapping
with open("comm.json", "w") as f:
    json.dump(list(enc_comm.classes_), f)

# Export TorchScript model
example_input = torch.randn(1, 2).to(device)
traced_model = torch.jit.trace(model, example_input)
traced_model.save("timeslice.pt")

print("Saved timeslice.pt and comm.json")
