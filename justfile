
reset-db : 
    rm data.db ; touch data.db && sqlx migrate run

create-mig name:
    sqlx migrate add {{name}}