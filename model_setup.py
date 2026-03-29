#!/usr/bin/env python3
"""
TSM Layer - Local Model Setup
Downloads and configures local LLM from HuggingFace for sensitive data processing.
"""

import os
import json
from pathlib import Path

# Popular open-source models for local execution
RECOMMENDED_MODELS = {
    "1": {
        "name": "TinyLlama-1.1B-Chat",
        "id": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
        "size": "~2.2 GB",
        "memory": "4 GB RAM",
        "speed": "Fast",
        "description": "Smallest model, great for testing and low-resource machines"
    },
    "2": {
        "name": "Llama-3.2-3B-Instruct",
        "id": "meta-llama/Llama-3.2-3B-Instruct",
        "size": "~6 GB",
        "memory": "8 GB RAM",
        "speed": "Fast",
        "description": "Balanced performance and speed, recommended for most users"
    },
    "3": {
        "name": "Mistral-7B-Instruct",
        "id": "mistralai/Mistral-7B-Instruct-v0.3",
        "size": "~14 GB",
        "memory": "16 GB RAM",
        "speed": "Medium",
        "description": "High quality responses, requires more resources"
    },
    "4": {
        "name": "Llama-3.1-8B-Instruct",
        "id": "meta-llama/Llama-3.1-8B-Instruct",
        "size": "~16 GB",
        "memory": "16 GB RAM",
        "speed": "Medium",
        "description": "Latest Meta model with excellent instruction following"
    },
    "5": {
        "name": "CodeLlama-7B",
        "id": "codellama/CodeLlama-7b-Instruct-hf",
        "size": "~14 GB",
        "memory": "16 GB RAM",
        "speed": "Medium",
        "description": "Optimized for code analysis and generation"
    },
    "6": {
        "name": "Phi-3-Mini (Microsoft)",
        "id": "microsoft/Phi-3-mini-4k-instruct",
        "size": "~7.6 GB",
        "memory": "8 GB RAM",
        "speed": "Fast",
        "description": "Microsoft's efficient small model with strong performance"
    },
    "7": {
        "name": "Gemma-2B-IT (Google)",
        "id": "google/gemma-2b-it",
        "size": "~5 GB",
        "memory": "6 GB RAM",
        "speed": "Fast",
        "description": "Google's lightweight instruction-tuned model"
    },
    "8": {
        "name": "Custom (Enter HuggingFace Model ID)",
        "id": "custom",
        "size": "Varies",
        "memory": "Varies",
        "speed": "Varies",
        "description": "Use any HuggingFace model by entering its ID"
    }
}


def print_header():
    """Print setup header."""
    print("\n" + "=" * 60)
    print("         TSM LAYER - LOCAL MODEL SETUP")
    print("=" * 60)
    print("\nThis will download a local LLM from HuggingFace for processing")
    print("sensitive data privately (no cloud APIs).\n")


def print_models():
    """Display available models."""
    print("Available Models:\n")
    print(f"{'#':<4} {'Name':<30} {'Size':<12} {'Memory':<12} {'Speed':<8}")
    print("-" * 70)

    for key, model in RECOMMENDED_MODELS.items():
        print(f"{key:<4} {model['name']:<30} {model['size']:<12} {model['memory']:<12} {model['speed']:<8}")

    print("\nRecommended:")
    print("  - Low resources (4-8 GB RAM):  #1 or #2")
    print("  - Medium (16 GB RAM):          #3 or #4")
    print("  - Code-focused tasks:          #5")
    print("")


def select_model():
    """Let user select a model."""
    while True:
        choice = input("Select model number (1-8): ").strip()

        if choice in RECOMMENDED_MODELS:
            model = RECOMMENDED_MODELS[choice]

            if model["id"] == "custom":
                custom_id = input("\nEnter HuggingFace model ID (e.g., 'meta-llama/Llama-2-7b-chat-hf'): ").strip()
                if custom_id:
                    return custom_id
                else:
                    print("Invalid model ID. Try again.\n")
                    continue

            # Confirm selection
            print(f"\nSelected: {model['name']}")
            print(f"  Model ID: {model['id']}")
            print(f"  Size: {model['size']}")
            print(f"  Memory: {model['memory']}")
            print(f"  {model['description']}")

            confirm = input("\nProceed with this model? (y/n): ").strip().lower()
            if confirm == 'y':
                return model["id"]
            else:
                print("")
                continue
        else:
            print("Invalid choice. Please enter a number between 1-8.\n")


def get_hf_token():
    """Get HuggingFace token from user."""
    print("\n" + "-" * 60)
    print("HuggingFace Access Token")
    print("-" * 60)
    print("Some models (like Llama) require authentication.")
    print("\nSteps:")
    print("  1. Go to: https://huggingface.co/settings/tokens")
    print("  2. Create a token (read access is enough)")
    print("  3. Paste it below (or press Enter to skip)")
    print("")

    token = input("HuggingFace token (optional): ").strip()
    return token if token else None


def save_config(model_id: str, hf_token: str = None):
    """Save model configuration."""
    config_dir = Path.home() / ".tsm"
    config_dir.mkdir(exist_ok=True)

    config_file = config_dir / "config.json"

    config = {
        "local_model": {
            "model_id": model_id,
            "provider": "huggingface",
            "has_token": bool(hf_token)
        }
    }

    # Save token separately if provided
    if hf_token:
        token_file = config_dir / ".hf_token"
        token_file.write_text(hf_token)
        token_file.chmod(0o600)  # Secure permissions
        print(f"\n[+] Token saved to: {token_file}")

    # Save config
    config_file.write_text(json.dumps(config, indent=2))
    print(f"[+] Config saved to: {config_file}")


def download_model(model_id: str, hf_token: str = None):
    """Download model using transformers."""
    print("\n" + "=" * 60)
    print("DOWNLOADING MODEL")
    print("=" * 60)
    print(f"\nModel: {model_id}")
    print("This may take several minutes depending on model size...")
    print("")

    try:
        # Check if transformers is installed
        import transformers
        print("[+] transformers library found")
    except ImportError:
        print("[!] Installing transformers library...")
        import subprocess
        subprocess.check_call([
            "pip", "install", "-q",
            "transformers", "torch", "sentencepiece", "accelerate"
        ])
        print("[+] Libraries installed")
        import transformers

    try:
        from transformers import AutoTokenizer, AutoModelForCausalLM
        import torch

        # Set token if provided
        if hf_token:
            os.environ["HF_TOKEN"] = hf_token

        print(f"\n[1/2] Downloading tokenizer...")
        tokenizer = AutoTokenizer.from_pretrained(
            model_id,
            token=hf_token,
            trust_remote_code=True
        )
        print("[+] Tokenizer downloaded")

        print(f"\n[2/2] Downloading model (this may take a while)...")
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            token=hf_token,
            torch_dtype=torch.float16 if torch.cuda.is_available() else torch.float32,
            device_map="auto",
            trust_remote_code=True,
            low_cpu_mem_usage=True
        )
        print("[+] Model downloaded successfully!")

        # Test the model
        print("\n[TEST] Running quick test...")
        test_prompt = "Hello! Can you hear me?"
        inputs = tokenizer(test_prompt, return_tensors="pt")

        if torch.cuda.is_available():
            inputs = {k: v.cuda() for k, v in inputs.items()}

        with torch.no_grad():
            outputs = model.generate(**inputs, max_length=50)
            response = tokenizer.decode(outputs[0], skip_special_tokens=True)

        print(f"[+] Test successful!")
        print(f"    Input: {test_prompt}")
        print(f"    Output: {response[:100]}...")

        return True

    except Exception as e:
        print(f"\n[X] Error downloading model: {e}")
        print("\nTroubleshooting:")
        print("  1. Check your internet connection")
        print("  2. Verify the model ID is correct")
        print("  3. For gated models (Llama), ensure you have access on HuggingFace")
        print("  4. Try a different model")
        return False


def main():
    """Main setup flow."""
    print_header()
    print_models()

    # Select model
    model_id = select_model()

    # Get HF token if needed
    hf_token = get_hf_token()

    # Save configuration
    save_config(model_id, hf_token)

    # Ask if user wants to download now
    print("\n" + "=" * 60)
    print("READY TO DOWNLOAD")
    print("=" * 60)
    print(f"Model: {model_id}")
    print("")
    download_now = input("Download model now? (y/n): ").strip().lower()

    if download_now == 'y':
        success = download_model(model_id, hf_token)

        if success:
            print("\n" + "=" * 60)
            print("SETUP COMPLETE!")
            print("=" * 60)
            print("\nYour local model is ready. TSM will use it for sensitive data.")
            print("\nTry it:")
            print("  python cli_app.py run \"My SSN is 123-45-6789, help me\"")
            print("\nThe sensitive data will be processed locally!")
        else:
            print("\n[!] Model download failed. You can try again later by running:")
            print("    python model_setup.py")
    else:
        print("\n[i] Skipped download. Configuration saved.")
        print("    Model will be downloaded on first use.")
        print("\nTo download manually later:")
        print("    python model_setup.py")

    print("")


if __name__ == "__main__":
    main()
