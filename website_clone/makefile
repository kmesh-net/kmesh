# Build the Docker image for development
buildKmeshDevImage:
	@docker build -t kmesh-website-dev -f Dockerfile.dev .

# Run the Docker container for development
runKmeshDevContainer: buildKmeshDevImage
	@docker run -it --rm -p 3000:3000 -v $(shell pwd):/app kmesh-website-dev