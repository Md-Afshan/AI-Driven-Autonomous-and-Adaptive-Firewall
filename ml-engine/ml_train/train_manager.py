"""
Master training manager script that orchestrates both WAF and NIDS model training.
Supports training individual models or all models together.
"""
import argparse
import sys
import logging
from pathlib import Path

# Add parent directory to path to import training modules
sys.path.insert(0, str(Path(__file__).parent))

from train_waf import train_waf_model, train_waf_sample
from train_nids import train_nids_model, train_nids_sample

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def train_waf():
    """Train WAF model"""
    logger.info("=" * 80)
    logger.info("STARTING WAF (Web Application Firewall) TRAINING")
    logger.info("=" * 80)
    try:
        model, tokenizer, history = train_waf_model()
        logger.info("✓ WAF training completed successfully")
        return True
    except Exception as e:
        logger.error(f"✗ WAF training failed: {str(e)}")
        return False


def train_nids():
    """Train NIDS model"""
    logger.info("=" * 80)
    logger.info("STARTING NIDS (Network Intrusion Detection System) TRAINING")
    logger.info("=" * 80)
    try:
        model, scaler = train_nids_model()
        logger.info("✓ NIDS training completed successfully")
        return True
    except Exception as e:
        logger.error(f"✗ NIDS training failed: {str(e)}")
        return False


def train_all():
    """Train all models"""
    logger.info("=" * 80)
    logger.info("STARTING COMPREHENSIVE MODEL TRAINING (WAF + NIDS)")
    logger.info("=" * 80)
    
    waf_success = train_waf()
    logger.info("\n")
    nids_success = train_nids()
    
    logger.info("\n" + "=" * 80)
    logger.info("TRAINING SUMMARY")
    logger.info("=" * 80)
    logger.info(f"WAF Training:  {'✓ SUCCESS' if waf_success else '✗ FAILED'}")
    logger.info(f"NIDS Training: {'✓ SUCCESS' if nids_success else '✗ FAILED'}")
    
    return waf_success and nids_success


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='AI-Driven Firewall Model Training Manager',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python train_manager.py --mode waf      # Train only WAF model
  python train_manager.py --mode nids     # Train only NIDS model
  python train_manager.py --mode all      # Train all models
        """
    )
    
    parser.add_argument(
        '--mode',
        type=str,
        choices=['waf', 'nids', 'all'],
        default='all',
        help='Training mode: waf (SQL Injection detection), nids (DDoS detection), or all'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )

    parser.add_argument(
        '--sample-size',
        type=int,
        default=0,
        help='Optional: limit training to a smaller sample size for quick tests (0 = full dataset)'
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info(f"Training mode: {args.mode}")
    
    # Execute training
    if args.mode == 'waf':
        success = train_waf() if args.sample_size == 0 else train_waf_sample(args.sample_size)
    elif args.mode == 'nids':
        success = train_nids() if args.sample_size == 0 else train_nids_sample(args.sample_size)
    else:  # all
        # For combined mode, if sample-size provided, run both trainers with that limit
        if args.sample_size and args.sample_size > 0:
            success_waf = train_waf_sample(args.sample_size)
            logger.info("\n")
            success_nids = train_nids_sample(args.sample_size)
            success = success_waf and success_nids
        else:
            success = train_all()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
