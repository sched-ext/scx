#!/usr/bin/env python3

import sys
import json
import torch
import numpy as np

if len(sys.argv) < 3:
    print(f"Usage: {sys.argv[0]} TASK_NAME WEIGHT")
    sys.exit(1)

task_name = sys.argv[1]
weight = float(sys.argv[2])

# Load encoder
with open("comm.json") as f:
    COMM_NAMES = json.load(f)

def get_task_id(name: str) -> int:
    try:
        return COMM_NAMES.index(name)
    except ValueError:
        return -1

task_id = get_task_id(task_name)
if task_id == -1:
    print(f"Unknown task: {task_name}")
    sys.exit(1)

# Load normalization parameters
with open("norm.json") as f:
    norm = json.load(f)
X_min = norm["X_min"]
X_max = norm["X_max"]
y_max = norm["y_max"]

# Normalize inputs
task_range = X_max[0] - X_min[0] or 1.0
weight_range = X_max[1] - X_min[1] or 1.0
task_norm = (task_id - X_min[0]) / task_range
weight_norm = (weight - X_min[1]) / weight_range

input_tensor = torch.tensor([[task_norm, weight_norm]], dtype=torch.float32)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
input_tensor = input_tensor.to(device)

# Load TorchScript model
model = torch.jit.load("timeslice.pt").to(device)
model.eval()

# Predict timeslice
with torch.no_grad():
    output = model(input_tensor)       # run the model
    output_norm = output.item()        # get scalar
    pred_slice = abs(output_norm) * y_max

print(f"comm={task_name:<16} task_id={task_id:<4} weight={weight:<6} predicted_timeslice={pred_slice:>15.3f} [ok]")
