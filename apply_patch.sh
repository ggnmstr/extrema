#!/bin/bash

cp extrema_hook_patch.diff ../../
cd ../../
git apply extrema_hook_patch.diff
rm extrema_hook_patch.diff
