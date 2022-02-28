#!/bin/bash
#SBATCH --job-name=prov-train
#SBATCH --partition=Leo
#SBATCH --time=2:00:00
#SBATCH --mem=64GB
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=16
#SBATCH --gres=gpu:1

# Load python distribution
module load anaconda3/2020.11

# Activate local venv
conda activate alpine
echo $CONDA_DEFAULT_ENV

# Bash command for python script
python3 main.py -dataFolder ../VPN-Non-VPN/processed -classType application