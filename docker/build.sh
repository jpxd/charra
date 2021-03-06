#!/bin/bash
###############################################################################
# Build docker image.                                                         #
###############################################################################


# ---------------------------------------------------------------------------#
# --- PREAMBLE --------------------------------------------------------------#
# ---------------------------------------------------------------------------#

## sanity check -- list all required tools here
read -r -d '' tool_reqs <<- EOM
dirname
docker
id
whoami
EOM
while read tool; do
	if [ ! -x "$(command -v $tool)" ]; then
		## print error using the shell builtin echo command
		echo "Required tool '${tool}' not found or not executable!" >&2
		exit 2
	fi
done < <(echo "$tool_reqs")


# ---------------------------------------------------------------------------#
# --- MAIN ------------------------------------------------------------------#
# ---------------------------------------------------------------------------#

## change directory to the one this script is placed in
cd "$(dirname "$0")"

## go up one directory
cd ../


## variables
docker_image_config_file='./docker/docker-image.config'
. "$docker_image_config_file"

## sanity checks
for cfg_opt in \
	'DOCKER_IMAGE_VENDOR' \
	'DOCKER_IMAGE_NAME' \
	'DOCKER_IMAGE_VERSION'
do
	cfg_opt_val=$(eval "echo \${${cfg_opt}}")
	if [ -z "${cfg_opt_val}" ]; then
		echo "** Please set the '$cfg_opt' option in file '$docker_image_config_file'." >&2
		exit 1
	fi
done

## construct Docker image name
docker_image_fullname="${DOCKER_IMAGE_VENDOR}/${DOCKER_IMAGE_NAME}:${DOCKER_IMAGE_VERSION}"

## set variables
container_user="$(whoami)"
container_uid="$(id -u)"
container_gid="$(id -g)"

## build container
docker build \
	`#--build-arg "user=${container_user}"` \
	--build-arg "uid=${container_uid}" \
	--build-arg "gid=${container_gid}" \
	-t "$docker_image_fullname" \
	.
