#!/usr/bin/env python3

import sys
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import LabelEncoder
import json
import numpy as np

def prio_to_weight(prio: int) -> int:
    MAX_RT_PRIO = 100
    CGROUP_WEIGHT_MIN = 1
    CGROUP_WEIGHT_DFL = 100
    CGROUP_WEIGHT_MAX = 10000

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
    cg_weight = round(weight * CGROUP_WEIGHT_DFL / 1024)
    return max(CGROUP_WEIGHT_MIN, min(CGROUP_WEIGHT_MAX, cg_weight))

# =========================
# Load and preprocess trace
# =========================
df = pd.read_csv("trace.csv")

# Encode task names as integers
le = LabelEncoder()
df['task_encoded'] = le.fit_transform(df['prev_comm'])

# Convert kernel priority to weight
df['weight'] = df['prio'].apply(prio_to_weight)

# Inputs: encoded task name + weight
X = df[['task_encoded', 'weight']].values.astype(np.float32)

# Output: timeslice
y = df['timeslice'].values.astype(np.float32)

# Normalize input
X_min = X.min(axis=0)
X_max = X.max(axis=0)
X_range = np.where(X_max - X_min == 0, 1, X_max - X_min)
X_norm = (X - X_min) / X_range

# Normalize output
y_min = y.min() if y.min() != 0.0 else 1.0
y_max = y.max() if y.max() != 0.0 else 1.0
y_norm = y / y_max

# Convert to tensors
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
X_tensor = torch.tensor(X_norm, dtype=torch.float32).to(device)
y_tensor = torch.tensor(y_norm, dtype=torch.float32).view(-1, 1).to(device)

# =========================
# Define the neural network
# =========================
class TimeSliceNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(2, 32),
            nn.ReLU(),
            nn.Linear(32, 32),
            nn.ReLU(),
            nn.Linear(32, 32),
            nn.ReLU(),
            nn.Linear(32, 1)
        )

    def forward(self, x):
        return self.net(x)

model = TimeSliceNet().to(device)

# Loss and optimizer
criterion = nn.L1Loss()
optimizer = optim.AdamW(model.parameters(), lr=1e-5)

# =========================
# Training loop
# =========================
epochs = 5000
prev = 1.0
for epoch in range(epochs):
    model.train()
    optimizer.zero_grad()
    outputs = model(X_tensor)
    loss = criterion(outputs, y_tensor)
    loss.backward()
    optimizer.step()

    if epoch % 10 == 0:
        print(f"Epoch {epoch:03d}, Loss: {loss.item():.6f}")
    if loss.item() < 1e-4 or prev < loss.item():
        break
    prev = loss.item()

# =========================
# Save encoder + model
# =========================
with open("comm.json", "w") as f:
    json.dump(list(le.classes_), f)

# Save normalization parameters
norm_params = {
    "X_min": X_min.tolist(),
    "X_max": X_max.tolist(),
    "y_min": float(y_min),
    "y_max": float(y_max),
}
with open("norm.json", "w") as f:
    json.dump(norm_params, f)

# Export TorchScript model
example_input = torch.randn(1, 2).to(device)
traced_model = torch.jit.trace(model, example_input)
traced_model.save("timeslice.pt")

print("Saved comm.json, norm.json, and timeslice.pt (neural network)")
