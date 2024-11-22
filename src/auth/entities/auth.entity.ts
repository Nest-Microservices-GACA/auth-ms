import { BeforeInsert, BeforeUpdate, Column, Entity, JoinColumn, ManyToOne, OneToMany, PrimaryGeneratedColumn } from "typeorm";

@Entity('cat_colaborador')
export class Auth {

    @PrimaryGeneratedColumn('identity')
    idu_usuario: string;

    @Column({
        type: 'varchar', 
        length:255, 
        unique:true
    })
    numero_empleado: string;

    @Column({
        type: 'varchar', 
        length:255, 
        unique:true
    })
    nom_correo: string;

    @Column('text', {
        select: false
    })
    nom_contrasena: string;

    @Column({
        type: 'varchar', 
        length:255,
    })
    nom_usuario: string;

    @Column('bool', {
        default: true
    })
    esactivo: boolean;

    @Column({
        type: 'int',
        name: 'idu_rol',
    })
    idu_rol: number;

    @BeforeInsert()
    checkFieldsBeforeInsert() {
        this.nom_correo = this.nom_correo.toLowerCase().trim();
    }

    @BeforeUpdate()
    checkFieldsBeforeUpdate() {
        this.checkFieldsBeforeInsert();   
    }


}
