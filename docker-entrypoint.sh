#!/bin/bash
set -e

if [ "$1" = 'cyhy-report' ]; then
  cyhy-report ${@:2}
elif [ "$1" = 'cyhy-cybex-scorecard' ]; then
  cyhy-cybex-scorecard ${@:2}
elif [ "$1" = 'cyhy-bod-scorecard' ]; then
  cyhy-bod-scorecard ${@:2}
elif [ "$1" = 'cyhy-m1513-scorecard' ]; then
  cyhy-m1513-scorecard ${@:2}
else
  echo "Usage:"
  echo "  docker run [DOCKER OPTIONS] dhub.ncats.dhs.gov:5001/cyhy-reports cyhy-report [OPTIONS]"
  echo "  docker run [DOCKER OPTIONS] dhub.ncats.dhs.gov:5001/cyhy-reports cyhy-cybex-scorecard [OPTIONS]"
  echo "  docker run [DOCKER OPTIONS] dhub.ncats.dhs.gov:5001/cyhy-reports cyhy-bod-scorecard [OPTIONS]"
  echo "  docker run [DOCKER OPTIONS] dhub.ncats.dhs.gov:5001/cyhy-reports cyhy-m1513-scorecard [OPTIONS]"
fi
