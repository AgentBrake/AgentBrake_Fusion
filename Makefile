.PHONY: bootstrap run demo test package clean

bootstrap:
	python --version
	bash scripts/bootstrap.sh

run:
	bash scripts/run_all.sh

demo:
	bash scripts/run_demo.sh

test:
	bash scripts/run_tests.sh

package:
	python scripts/package_submission.py

clean:
	rm -rf dist .pytest_cache .pytest_tmp web/studio/dist
