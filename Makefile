.PHONY: demo test check clean

demo:
	python src/leaklens.py \
		--log sample-output/direct_leak.info sample-output/network_leak.info sample-output/log_leak.info sample-output/benign.info sample-output/realistic_formats.info \
		--outdir reports

test:
	python -m unittest discover -s tests -v

check:
	python -m compileall src tests
	python -m unittest discover -s tests -v

clean:
	find . -type d -name '__pycache__' -prune -exec rm -rf {} +
	find . -type f -name '*.pyc' -delete
