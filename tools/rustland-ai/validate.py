#!/usr/bin/env python3

import sys
import torch
import json
import numpy as np
from sklearn.preprocessing import LabelEncoder

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = torch.jit.load("timeslice.pt").to(device)
model.eval()

# Fake input.
example = {
    "comm": 0,
    "weight": 100,
}

# Build input tensor.
input_tensor = torch.tensor(
    [[example["comm"], example["weight"]]],
    dtype=torch.float32,
    device=device
)

# Predict time slice.
with torch.no_grad():
    output = model(input_tensor)
    pred_slice = int(output.item())
    print(f"task={example['comm']} weight={example['weight']} ts={pred_slice} [ok]")
