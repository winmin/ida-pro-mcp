FROM ida-pro:latest

ENV TRANSPORT="http://0.0.0.0:8745"
ENV MAX_INSTANCES=10
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

ENV PATH="/root/.local/bin:${PATH}"

# Copy project
COPY . /opt/ida-pro-mcp

WORKDIR /opt/ida-pro-mcp

# Install project dependencies
RUN uv sync

EXPOSE 8745

ENTRYPOINT ["sh", "-c", "exec uv run idalib-pool --transport $TRANSPORT --max-instances $MAX_INSTANCES"]
