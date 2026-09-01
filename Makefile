up:
	docker compose -f docker/docker-compose.yml up -d --build

down:
	docker compose -f docker/docker-compose.yml down

restart:
	docker compose -f docker/docker-compose.yml restart

logs:
	docker compose -f docker/docker-compose.yml logs -f

logs-app:
	docker compose -f docker/docker-compose.yml logs -f app

status:
	docker compose -f docker/docker-compose.yml ps

rebuild:
	docker compose -f docker/docker-compose.yml down
	docker compose -f docker/docker-compose.yml up -d --build

clean:
	docker compose -f docker/docker-compose.yml down -v
