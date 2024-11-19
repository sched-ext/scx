#!/bin/bash
yaml_file="$1"

system_info=$(yq e '.system-info' $yaml_file)

metrics=$(yq e '.metrics[]' $yaml_file)
# Create JSON array
json_array=()
# Iterate over metrics
# Iterate over metrics
while IFS= read -r line; do
  key=$(echo "$line" | yq e 'keys[]')
  value=$(echo "$line" | yq e '.[]')
  # Skip stressor field
  if [ "$key" == "stressor" ]; then
    continue
  fi
  # Create JSON object
  json_object=$(jq -n \
    --arg name "$key" \
    --arg unit "data" \
    --argjson value $(echo "$value" | tr -d '"') \
    '{name: $name, unit: $unit, value: $value}')
  json_array+=("$json_object")
done <<< "$metrics"
# Print JSON array
echo "["
for ((i = 0; i < ${#json_array[@]}; i++)); do
  echo "  ${json_array[$i]}"
  if ((i < ${#json_array[@]} - 1)); then
    echo ","
  fi
done
echo "]"
